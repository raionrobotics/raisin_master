# raisin 영상 UDP 전송 기능 개발 명세서

| 항목 | 내용 |
|---|---|
| 문서 버전 | v0.1 초안 |
| 작성일 | 2026-11-02 |
| 작성 | SW개발팀 (초안) |
| 근거 | 로컬 `raisin_master` 소스 (`raisin` 0.3.17, `raisin_gui` 0.2.16, `raisin_plugin` 0.3.15) |
| 상태 | 설계안 선택(5장) 전 초안. 11장 미결 항목이 닫히면 v1.0으로 올린다 |

## 0. 한 줄 결론

지금은 영상(`FfmpegPacket`)이 제어·상태 메시지와 **같은 TCP 연결의 같은 묶음 프레임**에 실려 간다. 무선 손실이 생기면 TCP 재전송이 끝날 때까지 영상뿐 아니라 그 연결의 모든 메시지가 같이 멈춘다. **영상 토픽만 선택적으로 UDP 사이드 채널로 빼고, 협상·키프레임 요청·폴백은 기존 TCP 연결로 처리한다.** 손실된 프레임은 재전송하지 않고 버린 뒤 다음 키프레임부터 다시 그린다. 기존 노드와의 호환은 프로토콜 버전을 올리지 않고 지금 비어 있는 필드로 협상해 유지한다.

## 1. 목적과 범위

### 1.1 목적

로봇 → 운용자 GUI 영상 경로의 지연 급증과 정지(freeze)를 줄이고, 영상 트래픽이 제어 메시지를 막지 않게 한다.

### 1.2 범위

- 포함: `raisin_network`의 UDP 데이터 채널(협상·분할·재조립·암호화·폴백), `FFMPEGEncoder` 키프레임 강제 API, GUI 영상 창(`raisin_gui_ffmpeg_window`)의 전송 방식 선택, 시험 하네스
- 제외: 노드 탐색용 UDP 멀티캐스트(이미 있음, 변경 없음), WebSocket 연결, 프로세스 플러그인의 서브프로세스 → 본 프로세스 구간(같은 호스트 TCP, 손실 없음), 외부 VMS용 RTSP(`raisin_onvif_plugin`)

### 1.3 관련 코드

| 위치 | 내용 |
|---|---|
| `src/raisin/raisin_network/src/network.cpp` | 송신 `messageSendLoop`(1813), 묶음 조립 `compileRawBytesForRemote`(1892)·`constructTcpMessage`(2264), 수신 `processRawBytesFromRemote`(2015)·`deserializeMessage`(2088) |
| `src/raisin/raisin_network/include/raisin_network/helper.hpp` | `Remote::NetworkType {TCP, WEBSOCKET}`(299), `NetworkMessageType`(198), `Connection`(305) |
| `src/raisin/raisin_network/include/raisin_network/network.hpp` | `version_ = 1104`(488), `unacknowledgedMsgThresholdForNewMsg_ = 50`(454) |
| `src/raisin/raisin_network/include/raisin_network/message_base.hpp` | `sendQueueThreshold = 15`(115) |
| `src/raisin/raisin_ffmpeg_image_transport/` | `FFMPEGEncoder`/`FFMPEGDecoder`, `docs/sdd.md` |
| `src/raisin/raisin_interfaces/msg/FfmpegPacket.msg` | 실제 전송 메시지 타입 |
| `src/raisin_gui/raisin_gui_basic_windows/raisin_gui_ffmpeg_window/` | GUI 수신·디코딩 |
| `src/raisin_plugin/raisin_onvif_plugin/src/raisin_onvif_plugin/onvif_rtsp_server.cpp` | gst-rtsp-server 기반 RTP 재전송 (5장 안 B의 선례) |

## 2. 현행 구조 (기준선)

```
카메라 프로세스 ──TCP(localhost)──▶ 플러그인 *_repub ──TCP(무선)──▶ GUI
 FFMPEGEncoder                        Publisher<FfmpegPacket>          Subscriber → FFMPEGDecoder
```

1. **연결당 한 묶음.** `constructTcpMessage`가 그 연결로 나갈 클라이언트 요청·퍼블리셔 메시지·서비스 응답·구독 목록을 **하나의 프레임**으로 묶는다. 4000바이트를 넘으면 압축하고, 해시(32 B)를 붙이고, 순차 nonce를 붙여 암호화한다.
2. **묶음 단위 ACK 창.** 묶음마다 수신 측이 ACK(길이 0 프레임)를 돌려준다. 미확인 묶음이 50개(`unacknowledgedMsgThresholdForNewMsg_`)면 새 묶음을 만들지 않는다. 퍼블리셔별로 미확인이 15개(`sendQueueThreshold`)를 넘으면 그 퍼블리셔는 이번 묶음에서 빠진다.
3. **엄격한 nonce.** 수신 측은 nonce가 직전 값보다 크고 차이가 5 미만이 아니면 "illegal message"로 보고 **연결을 끊는다**(2032~2040행). 순서 뒤바뀜·유실을 전제로 하지 않는다.
4. **영상 부호화.** 플러그인 대부분이 큐 15로 `FfmpegPacket`을 발행한다. 인코더 기본값은 `GOPSize_ = 15`, `bitRate_ = 1 Mbps`, `max_b_frames = 0`, `preset=ultrafast`, `tune=zerolatency`. **키프레임을 즉시 강제하는 API는 없다.**
5. **기존 UDP.** `setupUdpSocket`/`udpLoop`는 노드 탐색 멀티캐스트 전용이다. 데이터는 UDP로 흐르지 않는다.

## 3. 문제 정의

| # | 증상 | 원인 (코드 근거) |
|---|---|---|
| P1 | 무선 손실 시 영상이 수백 ms~수 초 멈췄다가 몰아서 재생 | TCP 재전송·혼잡창 축소. 오래된 프레임도 반드시 도착해야 다음 프레임이 나간다 |
| P2 | 영상이 많을 때 제어·상태 메시지도 늦게 도착 | 1번 묶음 구조. 큰 키프레임 묶음이 같은 연결의 다른 메시지를 가로막음(head-of-line blocking) |
| P3 | 지연이 쌓이면 일정 시간 영상이 아예 안 옴 | 2번 ACK 창. 미확인이 15를 넘으면 영상 퍼블리셔가 묶음에서 빠짐 |
| P4 | 손실 후 화면 깨짐이 길게 지속될 수 있음 (UDP 도입 시 새로 생기는 문제) | 키프레임 강제 API 부재. 최악 GOP 15프레임(30 fps 기준 0.5 s)을 기다려야 함 |

> P1~P3의 크기는 아직 측정하지 않았다. 9.2절 시험으로 기준선을 먼저 잰다.

## 4. 요구사항

| ID | 요구 | 검증 |
|---|---|---|
| FR-1 | 토픽 단위로 전송 방식(TCP/UDP)을 고를 수 있다. 기본값은 TCP(현행 동작 유지) | 단위·통합 |
| FR-2 | UDP 협상·키프레임 요청·상태 보고는 기존 TCP 연결로 한다 | 통합 |
| FR-3 | MTU를 넘는 패킷은 분할 송신하고 수신 측에서 재조립한다. 불완전한 프레임은 버린다 | 단위 |
| FR-4 | 프레임 유실을 감지하면 다음 키프레임까지 디코더 입력을 보류하고, 송신 측에 키프레임을 요청한다 | 단위·통합 |
| FR-5 | 인코더에 키프레임 강제 API(`requestKeyframe()`)를 추가한다 | 단위 |
| FR-6 | UDP가 일정 시간 안 들어오면(방화벽·NAT·터널) 자동으로 TCP로 되돌아가고 그 사실을 1회 경고한다 | 통합 |
| FR-7 | 구버전 노드와 연결해도 연결이 끊기지 않고 TCP로 동작한다 | 통합 (구버전 바이너리 대 신버전) |
| FR-8 | 연결에 암호화가 설정돼 있으면 UDP 패킷도 같은 `Encryption` 플러그인으로 암호화하고 해시로 무결성을 검사한다. 재전송 방어는 창(window) 방식으로 한다 | 단위 |
| FR-9 | GUI 영상 창에서 전송 방식과 손실률·재조립 실패 수를 볼 수 있다 | 수동 |
| FR-10 | Linux와 Windows(GUI) 둘 다 지원한다 (`network.cpp`의 `_WIN32` 분기와 동일 범위) | 빌드 |
| NFR-1 | 손실 5 %·지연 30 ms 망에서 영상 정지 최대 시간이 TCP 대비 줄어든다 (목표치는 9.2 기준선 측정 후 확정) | 9.2 |
| NFR-2 | 영상 부하 중 제어 메시지 왕복 지연이 영상 없음 대비 크게 늘지 않는다 (목표치 동일) | 9.2 |
| NFR-3 | UDP 송신이 무선 링크를 폭주시키지 않도록 프레임 단위 페이싱을 한다 | 9.2 |

## 5. 설계안 비교

| 안 | 내용 | 장점 | 단점 |
|---|---|---|---|
| **A. raisin_network UDP 사이드 채널 (추천)** | 기존 Publisher/Subscriber API는 그대로, 구독 시 UDP를 선택하면 해당 토픽만 UDP로 보냄 | 플러그인 코드 변경 거의 없음. 기존 암호화·탐색·연결 관리 재사용. GUI 수정 작음 | `raisin_network`(핵심 라이브러리) 변경. 분할·재조립·nonce를 직접 구현 |
| B. RTSP/RTP (gst-rtsp-server) | onvif 플러그인처럼 로봇에서 RTSP 서버를 열고 GUI가 RTSP 클라이언트로 수신 | 표준 프로토콜, VLC·외부 VMS 호환, 선례 있음 | GUI에 GStreamer/RTSP 클라이언트 의존성 추가. raisin 암호화·연결 관리 밖. 토픽 메타데이터(헤더 스탬프·검출 오버레이 동기화) 별도 처리 |
| C. 영상 전용 TCP 연결 분리 | 영상만 별도 TCP 소켓 | 구현 쉬움, P2 해결 | P1(재전송 정지) 그대로 |

추천 근거: P1·P2를 둘 다 푸는 것은 A와 B다. 운용 GUI는 raisin 토픽 기반이고 검출 결과(`detectionTopic_`)와 영상 스탬프 동기화를 이미 raisin 메시지로 하고 있어 A가 변경 범위가 작다. 외부 VMS 연동은 지금처럼 onvif 플러그인(B)이 따로 맡는다.

**이하 6~8장은 A안 기준이다.**

## 6. 상세 설계 (A안)

### 6.1 협상 — 프로토콜 버전을 올리지 않는다

`version_`이 다르면 상대가 연결을 끊는다(2097행). 그래서 새 `NetworkMessageType`을 추가하거나 버전을 올리면 구버전과 섞인 현장에서 연결이 끊긴다. 대신 **구독 목록 항목의 비어 있는 32비트 필드**를 쓴다.

- 현재 송신: `setBuffer(mts, NetworkMessageType::SUBSCRIBER, m.first, int32_t(0))` (2378행) — 항상 0
- 현재 수신: `getBuffer(buffer, messageType, title, id)`로 읽지만 SUBSCRIBER일 때 `id`를 쓰지 않는다 (2134, 2209행)

| 비트 | 의미 |
|---|---|
| 0–15 | 구독자 UDP 수신 포트 (0이면 TCP 요청 = 현행) |
| 16–23 | 전송 옵션 플래그 (bit16 = UDP 요청, 나머지 예약) |
| 24–31 | UDP 채널 버전 (1부터) |

| 퍼블리셔 \ 구독자 | 구버전 (필드 0) | 신버전 UDP 요청 |
|---|---|---|
| 구버전 | TCP (현행) | 필드 무시 → TCP. 구독자는 6.6 폴백으로 TCP 유지 |
| 신버전 | TCP | UDP |

퍼블리셔는 UDP를 수락하면 그 연결의 묶음 프레임에 들어가는 **헤더 공유 메시지**(`messageHeader_`, 1초 주기)에 `토픽 → streamId, 송신 포트` 표를 붙여 알린다. 구버전 수신 측이 이 확장을 무시하도록 붙이는 위치·형식은 구현 시 `processHeaderMessageFromTcp` 파서를 보고 정한다 (11장 미결 Q3).

### 6.2 UDP 소켓

- 노드당 데이터 UDP 소켓 1개(송수신 공용, 탐색용 멀티캐스트 소켓과 별개). 포트는 OS 할당(0 바인드) 후 협상으로 알린다
- 목적지 = TCP 연결의 상대 IP + 협상된 포트. 수신 측은 **송신 IP가 해당 연결의 상대 IP와 같은 패킷만** 받는다
- `SO_SNDBUF`/`SO_RCVBUF`를 키프레임 몇 장 분량(예: 1 MB)으로 늘린다. 실제 적용값은 로그로 1회 남긴다
- 스레드: 수신 루프 1개 + 송신은 퍼블리셔 이벤트에서. 스레드 그룹은 인자로 받고 기본값은 기존 네트워크 스레드와 같게 한다

### 6.3 패킷 형식

`FfmpegPacket` 하나를 직렬화한 바이트열을 "프레임"이라 하고, 이를 조각(fragment)으로 나눈다.

| 필드 | 크기 | 설명 |
|---|---|---|
| magic | 2 B | `0x5256` ("RV") |
| channelVersion | 1 B | 1 |
| flags | 1 B | bit0 키프레임, bit1 암호화 |
| streamId | 2 B | 협상에서 받은 토픽 식별자 |
| frameSeq | 4 B | 스트림별 프레임 번호 (1씩 증가) |
| fragIndex / fragCount | 2 B / 2 B | 조각 번호 / 총 조각 수 |
| frameBytes | 4 B | 프레임 전체 길이 (재조립 버퍼 크기) |
| payload | ≤ 1200 B (설정) | 조각 데이터 |
| (암호화 시) | — | 위 헤더 뒤 전체가 6.7의 암호문으로 대체됨 |

- 조각 크기 기본 1200 B: IP 분할이 일어나지 않게 일반 무선·VPN 경로 MTU보다 작게 잡는다
- 크기 감: 1 Mbps·30 fps면 평균 프레임 약 4 KB(4조각). 키프레임은 그 몇 배로, 수십 조각이 될 수 있다 (추정 — 9.2에서 실측)

### 6.4 수신 재조립과 유실 처리

1. `(streamId, frameSeq)`별 버퍼에 조각을 모은다. 모두 모이면 역직렬화해 기존 구독 콜백 경로(`addNewMessageReceived` → `triggerTask`)로 넘긴다. **콜백 쪽 코드는 TCP와 같은 경로를 탄다**
2. 더 새로운 프레임이 완성됐거나 `reassemblyTimeout`(기본 100 ms)이 지나면 미완성 프레임은 버린다
3. `frameSeq`에 구멍이 생기면 "동기 끊김" 상태로 바꾸고, 다음 키프레임이 완성될 때까지 프레임을 넘기지 않는다 (깨진 참조 프레임으로 디코딩하지 않기 위함)
4. 동기 끊김 상태에서 TCP 경로로 키프레임 요청을 보낸다. 요청은 스트림당 `keyframeRequestInterval`(기본 200 ms)에 한 번만
5. 순서가 바뀌어 도착한 조각도 받는다 (프레임 버퍼 기준이므로 조각 순서 무관)

### 6.5 송신 측

- 퍼블리셔는 UDP 구독 연결에 대해 `clientSpecificMessageToSend` 큐에 넣지 않고 UDP 송신 큐에 넣는다. **큐가 차면 가장 오래된 프레임을 버린다** (TCP처럼 쌓아 두지 않음)
- 페이싱: 한 프레임의 조각을 한꺼번에 쏘지 않고 프레임 간격 안에 고르게 나눈다 (NFR-3)
- ACK 창(2장 2번)에는 포함되지 않는다. UDP 영상은 TCP 묶음 ACK 수에 영향을 주지 않는다
- 키프레임 요청 수신 → 해당 토픽의 인코더에 `requestKeyframe()` 전달. 퍼블리셔와 인코더가 다른 프로세스(`*_process_runner` → `*_repub`)인 플러그인은 요청을 서브프로세스로 넘기는 서비스가 필요하다 (8장 파급 목록)

### 6.6 폴백

- 구독자: UDP를 요청한 뒤 `udpFallbackTimeout`(기본 3 s) 동안 해당 토픽 패킷이 하나도 없으면 필드를 0으로 다시 보내 TCP로 되돌린다. `RSWARN` 1회 (로그 남발 금지 규칙)
- 원격 경로(frp 등 TCP 터널, NAT 너머)에서는 UDP가 통과하지 못한다고 보고 이 폴백에 맡긴다
- 연결이 끊겼다 다시 붙으면 협상부터 다시 한다

### 6.7 암호화와 무결성

현재 TCP는 묶음마다 해시(32 B) + 순차 nonce 검사를 한다. UDP는 유실·순서 뒤바뀜이 정상이므로 그대로 쓸 수 없다.

현재 암호화는 `raisin::Encryption` 플러그인 인터페이스(`encrypt(plaintext, ciphertext)`/`decrypt(...)` 두 함수, `src/raisin/raisin_encryption/raisin_encryption/include/raisin_encryption/raisin_encryption.hpp`)이고, 구현체는 `raisin_empty_encryption`과 `raisin_aes256_encryption`(AES-256-CBC, `EVP_aes_256_cbc`)이다. 인증 암호화(AEAD) API는 없다.

- **1차 구현은 TCP와 같은 방식을 조각 단위로 재사용한다.** 평문 = 6.3 헤더 중 `streamId·frameSeq·fragIndex` + payload + 해시(32 B) → `Network::encrypt()`. 수신 측은 `decrypt()` 후 해시를 검사하고, 평문 안의 헤더가 바깥 헤더와 같은지 확인한다
- nonce 검사는 TCP의 "직전보다 크고 차이 5 미만" 대신 **최근 `frameSeq` 64개 창 비트맵**으로 한다. 창 밖·중복은 버리되 연결은 끊지 않는다 (UDP에서 유실·뒤바뀜은 정상)
- 해시 32 B와 CBC 패딩(최대 16 B)이 조각마다 붙으므로 오버헤드는 조각당 약 4 %다 (1200 B 기준)
- 참고: AES 구현이 IV를 멤버(`iv_`)로 들고 있어 고정 IV로 보인다. 이 문제는 TCP에도 똑같이 있는 기존 사항이라 본 작업 범위 밖으로 두고 11장 R4로 기록만 한다

### 6.8 관측성

`Connection`에 UDP 스트림별 카운터(수신 조각, 완성 프레임, 버린 프레임, 키프레임 요청 수)를 추가하고 GUI 영상 창에 표시한다 (FR-9). 기존 `publisherTraffic`/`subscriberTraffic` 집계에도 넣어 트래픽 창에서 보이게 한다.

## 7. 인터페이스 명세

### 7.1 API

```cpp
// raisin_network — 구독 시 전송 방식 지정 (기본 TCP, 기존 호출은 그대로 컴파일)
enum class Transport : uint8_t { TCP = 0, UDP };
template <typename T, typename CallbackT>
std::shared_ptr<Subscriber<T>> createSubscriber(const std::string& title,
    std::shared_ptr<Remote::Connection> connection, CallbackT&& callback,
    const std::string& owner_override = "", Transport transport = Transport::TCP);

// 퍼블리셔 — 키프레임 요청 수신 콜백
void Publisher<T>::setKeyframeRequestCallback(std::function<void()> callback);

// ffmpeg_image_transport
void FFMPEGEncoder::requestKeyframe();  // 다음 프레임을 AV_PICTURE_TYPE_I로 인코딩
```

UDP 허용 대상은 1차로 `raisin_interfaces::msg::FfmpegPacket`(및 동일 필드의 `FFMPEGPacket`)만으로 제한한다. 다른 타입은 UDP를 요청해도 TCP로 처리하고 1회 경고한다.

### 7.2 파라미터 (신규)

| 키 | 기본값 | 위치 | 설명 |
|---|---|---|---|
| `udp_video.enable` | `true` | 노드 네트워크 설정 | 퍼블리셔가 UDP 요청을 수락할지 |
| `udp_video.fragment_bytes` | 1200 | 동일 | 조각 payload 크기 |
| `udp_video.reassembly_timeout_ms` | 100 | 동일 | 미완성 프레임 폐기 시간 |
| `udp_video.keyframe_request_interval_ms` | 200 | 동일 | 키프레임 요청 최소 간격 |
| `udp_video.fallback_timeout_ms` | 3000 | 동일 | TCP 폴백 판정 시간 |
| GUI 영상 창 "Transport" 선택 | TCP | GUI 창 설정 | 창별 TCP/UDP 선택 |

파라미터 파일 위치(노드 설정 vs `configuration_setting.yaml`)는 구현 시 기존 네트워크 설정 키 관행을 조사해 정한다.

## 8. 변경 파급 목록 (Ripple Sweep)

- [ ] `src/raisin/raisin_network` — UDP 채널, 협상 필드, 헤더 확장, 폴백, 카운터
- [ ] `src/raisin/raisin_ffmpeg_image_transport` — `requestKeyframe()`
- [ ] `src/raisin/raisin_interfaces` — 변경 없음 예정 (메시지 필드 유지)
- [ ] `src/raisin_gui/.../raisin_gui_ffmpeg_window` — 전송 방식 선택, 통계 표시, 동기 끊김 시 마지막 정상 프레임 유지
- [ ] `src/raisin_plugin` 카메라 플러그인 (d435/d455/d430/oak/boson/i3system/harrier/yolox repub) — 키프레임 요청을 서브프로세스 인코더로 전달하는 경로
- [ ] `src/raisin_plugin/raisin_sensors` 시뮬레이션 카메라, `src/raisin_test_plugin/raisin_line_tracer_plugin` — 같은 메시지 사용처 (프로덕션 아님, 누락 주의)
- [ ] `src/raisin/release.yaml` version 상향 + `raisin_gui`·`raisin_plugin` `release.yaml`의 `raisin>=` 하한 상향. 배포 순서: `raisin` 먼저
- [ ] `docs/` + `raisin_ffmpeg_image_transport/docs/sdd.md` 갱신

확인하지 않은 축: 로컬에 없는 설정 레포(`raibo-config` 등 org 레포)의 네트워크 설정, 방화벽(로봇 OS의 ufw/iptables) 설정, gitnexus 호출 그래프.

## 9. 시험 및 검증 계획

### 9.1 단위·통합 (`python3 raisin.py test debug -p raisin_network`)

| 테스트 | 분류 | 확인 내용 |
|---|---|---|
| 분할/재조립 | unit | 임의 크기 프레임 왕복, 조각 순서 섞기, 중복 조각, 1조각 유실 시 폐기 |
| 동기 끊김 | unit | 구멍 발생 → 키프레임 전까지 미전달 → 키프레임 후 재개 |
| nonce 창 | unit | 창 밖·중복 `frameSeq` 거부, 순서 뒤바뀜 허용 |
| 협상 호환 | integration | 신↔신 UDP, 신 구독↔구 퍼블리셔(필드 0 응답) TCP 유지, 연결 끊김 없음 |
| 폴백 | integration | UDP 포트 차단 → 3 s 후 TCP로 영상 계속 |
| 키프레임 강제 | integration (`ffmpeg_image_transport`) | `requestKeyframe()` 다음 패킷의 `flags`에 키프레임 표시 |
| 손실 환경 | integration | loopback에 `tc qdisc netem loss 5% delay 30ms` (root 필요 시 수동 시험으로 분리) |

### 9.2 성능 시험 (실기)

같은 카메라·비트레이트로 TCP와 UDP를 번갈아 측정한다. **구현 전에 TCP 기준선부터 잰다.**

| 지표 | 측정 방법 |
|---|---|
| 영상 정지 최대·누적 시간 | GUI 수신 프레임 간격 > 3 × 프레임 주기인 구간 |
| 화면 지연 | 카메라 앞 타임스탬프 화면을 찍어 GUI 화면과 비교 (CLI 타임스탬프는 묶여 찍히므로 쓰지 않는다) |
| 제어 메시지 지연 | 영상 부하 중 서비스 왕복 시간 |
| 손실률·키프레임 요청 수 | 6.8 카운터 |
| 조건 | 유선, 무선 근거리, 무선 원거리(손실 발생 거리), 카메라 2대 동시 |

### 9.3 완료 보고

`report/unittest.md`, `report/asan.md`, `report/tsan.md`(수신 스레드 추가로 TSan 필수)의 실제 수치와 9.2 표를 인용한다. 돌리지 않은 시험은 돌리지 않았다고 적는다.

## 10. 단계별 개발 계획 (제안)

| 단계 | 내용 | 산출물 |
|---|---|---|
| 0 | TCP 기준선 측정 (9.2) | 측정 표 — NFR 목표치 확정 |
| 1 | `requestKeyframe()` + 테스트 | `ffmpeg_image_transport` PR |
| 2 | UDP 채널 코어 (패킷 형식·분할·재조립·nonce) + 단위 테스트 | `raisin_network` PR |
| 3 | 협상·폴백·키프레임 요청 경로 + 통합 테스트 | `raisin_network` PR |
| 4 | GUI 선택·통계, 카메라 플러그인 키프레임 전달 | `raisin_gui`, `raisin_plugin` PR |
| 5 | 실기 비교 시험, 기본값 결정 (UDP를 기본으로 할지) | 시험 보고서 |

## 11. 리스크와 미결 사항

| # | 내용 | 결정 필요 대상 |
|---|---|---|
| Q1 | 설계안 A/B 중 선택 (본 문서는 A 추천) | 팀 |
| Q2 | 운용 무선망(메시 라디오 등)이 UDP를 통과시키는지, 원격 운용이 TCP 터널(frp 등)을 쓰는지 | 현장·인프라 |
| Q3 | 헤더 공유 메시지에 `streamId` 표를 붙일 때 구버전 파서가 무시하는지 — `processHeaderMessageFromTcp` 확인 후 안 되면 다른 무시 가능 필드를 찾는다 | 구현 |
| Q4 | 조각마다 `encrypt()`를 부를 때 CPU 부하 (카메라 여러 대 × 30 fps × 조각 수). 9.2에서 측정 | 9.2 |
| Q5 | 메시지 타입이 두 개(`FFMPEGPacket`, `FfmpegPacket`)인 문제 — UDP 허용 대상에 둘 다 넣을지 | 구현 |
| R1 | `raisin_network`는 모든 노드가 쓰는 핵심 라이브러리라 회귀 위험이 크다. 기본값을 TCP로 두고 옵트인으로 시작한다 | — |
| R2 | 키프레임 요청이 잦으면 비트레이트가 튄다. 요청 간격 제한과 GOP 설정을 함께 조정해야 한다 | 9.2 |
| R3 | 페이싱 없이 키프레임 수십 조각을 한꺼번에 쏘면 무선 큐에서 같이 유실된다 | 9.2 |
| R4 | `raisin_aes256_encryption`이 고정 IV(`iv_` 멤버)로 CBC를 쓰는 것으로 보인다. 기존 TCP에도 있는 사항이라 별도 이슈로 다룬다 | 보안 검토 |

## 12. 용어

| 용어 | 뜻 |
|---|---|
| 묶음 프레임 | raisin_network가 한 연결로 보낼 여러 메시지를 합쳐 만든 TCP 전송 단위 |
| head-of-line blocking | 앞 데이터가 재전송을 기다리는 동안 뒤 데이터가 전부 대기하는 현상 |
| GOP | Group of Pictures. 키프레임과 키프레임 사이 간격(프레임 수) |
| 키프레임 (I-frame) | 다른 프레임 없이 단독으로 디코딩되는 프레임. 유실 후 화면 복구의 시작점 |
| MTU | 한 번에 보낼 수 있는 IP 패킷 최대 크기. 넘으면 IP 단에서 쪼개져 유실에 취약해짐 |
