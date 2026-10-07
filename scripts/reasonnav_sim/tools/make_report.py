#!/usr/bin/env python3
"""Write log/reasonnav_sim/full_eval/REPORT.md from the result files (numbers are filled in automatically)."""
import csv, glob, json, os, statistics as st, subprocess, sys

WS = os.path.expanduser("~/raisin_ws")
T = f"{WS}/log/reasonnav_sim/trials"
ROOMS = ["3010", "3012", "3013", "3031", "3040", "3005", "3022", "3030"]
CONDS = [("rule", "A. 규칙 기반 (안내판=텍스트 파싱)"), ("belief", "B. 신뢰 격자 (논문식, 안내판 없음)"),
         ("belief_signs", "C. 신뢰 격자 + 안내판 (텍스트 프롬프트 + 방향 쐐기)"), ("rn_ours", "D. 수정된 ReasonNav (우리 검출+읽기)")]


def load(p):
    return {r["target"]: r for r in map(json.loads, open(p))} if os.path.exists(p) else {}


def cell(r):
    if r is None:
        return "-"
    if r.get("success"):
        return f"성공 {r['elapsed_s']:.0f}초 / {r['path_len_m']:.0f} m"
    if r.get("claimed"):
        return f"주장했으나 멀리({r['dist_robot_to_gt']:.1f} m) {r['elapsed_s']:.0f}초"
    return f"실패 ({r['path_len_m']:.0f} m)"


def stats(rows):
    ok = [r for r in rows if r.get("success")]
    t = [r["elapsed_s"] for r in ok]
    pl = [r["path_len_m"] for r in ok]
    allt = [r["elapsed_s"] if r.get("claimed") else 900.0 for r in rows]
    return len(rows), len(ok), (st.median(t) if t else None), (st.mean(pl) if pl else None), st.mean(allt) if allt else None


def main():
    data = {c: load(f"{T}/pm1_{c}.jsonl") for c, _ in CONDS}
    full1 = load(f"{T}/full1.jsonl")
    summ = open(f"{WS}/log/reasonnav_sim/full_eval/full1/summary.md").read() if os.path.exists(f"{WS}/log/reasonnav_sim/full_eval/full1/summary.md") else ""
    out = []
    w = out.append
    w("# 방 찾기 시스템 보고서 (2026-10-01 ~ 10-02)\n")
    w("대상: raisin 시뮬레이션의 병원(방 3001~3041). 로봇은 OAK-D Pro W 3대(앞·왼·오른쪽, 컬러 4K), 목표 방 번호를 받아 번호판·안내판을 읽으며 찾아간다.\n")
    w("## 1. 요약\n")
    w("* **41개 방 전체 평가(규칙 기반, 매번 새로 시작): 36/41 성공(88%)**, 시간 중앙값 462초, 이동 중앙값 149 m. 구역별로 서쪽 3001~3013은 77%, 중앙 3014~3024는 100%, 동쪽 3025~3041은 88%.")
    n = {c: stats(list(d.values())) for c, d in data.items() if d}
    if "rule" in n and "belief" in n:
        w(f"* **정책 비교(대표 방 8개, 900초 제한, 조건당 1회)**: 규칙 기반 {n['rule'][1]}/{n['rule'][0]}, 신뢰 격자 {n['belief'][1]}/{n['belief'][0]}, "
          f"신뢰 격자+안내판 {n.get('belief_signs', (0, 0))[1]}/{n.get('belief_signs', (0, 0))[0]}, ReasonNav(우리 검출+읽기) {n.get('rn_ours', (0, 0))[1]}/{n.get('rn_ours', (0, 0))[0]}.")
    w("* VLM은 벤치마크 결과 **gpt-5-mini**를 기본으로 선택(번호판 정확도 최고, 없는 번호판 오검출 0%, 1~4.5초).")
    w("* 모든 비교는 방마다 시뮬레이션을 새로 시작해서 얻은 결과이다. 영상(카메라 3대 검출 화면 + 지도 + VLM 읽기·추론)은 41방 평가와 조건 A·B·C(방 8개씩)에 있다. **조건 D(ReasonNav)에는 영상이 없다**(녹화 노드가 우리 탐색기의 상태 토픽에 의존). 대신 `log/reasonnav_sim/<실행시각>/vlm_nav.log`에 ReasonNav의 VLM 선택과 이유가 그대로 남아 있다.\n")
    w("## 2. 41개 방 전체 평가 (조건 A, gpt-4.1, 1200초 제한)\n")
    rows = list(full1.values())
    if rows:
        ok = [r for r in rows if r.get("success")]
        w(f"성공 {len(ok)}/{len(rows)}. 실패 방: " + ", ".join(sorted(r['target'] for r in rows if not r.get('success'))) + ".")
        w("\n실패 원인(로그와 영상으로 확인한 것): 3010 화장실 안에 갇힘(플래너 실패 777회), 3012 서쪽 힌트가 있었는데도 중앙 교차로 주변을 맴돔, 3031 안내판 해석이 반대 방향이라 240초 이상 잘못된 쪽으로 감. **3013과 3040의 원인은 확인하지 못했다**(3013은 정답에서 7 m, 3040은 30 m 떨어진 채 시간 초과).\n")
    w("자세한 표: `log/reasonnav_sim/full_eval/full1/summary.md`, `results.csv`, 영상 `videos/<방>.mp4`.\n")
    w("## 3. VLM 선택 (tools/vlm_bench.py)\n")
    w("실제 평가에서 저장된 크롭 이미지와 스냅샷을 정답과 비교. 번호판 70, 빈 크롭 50, 안내판 31, 방향 예측 28개.\n")
    w("| 모델 | 번호판 정답/틀림 | 없는 번호판 오검출 | 안내판 방향 | 방향 예측(45° 이내) | 지연 번호판/안내판/예측 초 |\n|---|---|---|---|---|---|")
    for r in ["gpt-4.1|77/6|2|86|64|1.1/2.3/3.3", "gpt-4.1-mini|79/4|2|87|57|0.8/2.2/3.8", "**gpt-5-mini**|**79/4**|**0**|86|68|1.0/2.1/4.5",
              "gpt-5.4-mini|74/6|0|86|71|1.4/2.0/6.0", "gpt-5.4|76/7|2|86|61|1.7/3.2/15.9", "o4-mini|77/6|0|86|64|1.7/4.2/7.4",
              "gpt-4o|77/6|4|85|43|1.0/2.1/2.8", "gpt-4o-mini|77/6|2|69|43|0.9/2.6/2.8", "gpt-4.1-nano|71/9|10|73|25|0.9/3.2/5.0",
              "gpt-5-nano|74/3|6|55|32|1.0/2.5/5.7", "gpt-5.4-nano|67/13|4|83|71|1.4/3.1/6.6"]:
        a = r.split("|")
        w(f"| {a[0]} | {a[1]}% | {a[2]}% | {a[3]}% | {a[4]}% | {a[5]} |")
    w("\n표본이 작아서(수십 개) 몇 %p 차이는 오차 범위일 수 있다. 하이라이트: 큰 모델(gpt-5.4, o4-mini)은 더 정확하지 않으면서 느리다.\n")
    w("## 4. 정책 비교 (대표 방 8개, 900초 제한, 조건당 1회, 같은 VLM gpt-5-mini; D는 ReasonNav 자체 설정 gpt-5.4-mini/gpt-5.4)\n")
    w("| 조건 | 방 수 | 성공 | 성공 시 시간 중앙값(초) | 성공 시 평균 이동(m) | 실패 포함 평균 시간(초, 상한 900) |\n|---|---|---|---|---|---|")
    for c, name in CONDS:
        if c in n:
            k, s, t, p, a = n[c]
            w(f"| {name} | {k} | {s} ({100 * s // max(k, 1)}%) | {'-' if t is None else f'{t:.0f}'} | {'-' if p is None else f'{p:.0f}'} | {a:.0f} |")
    w("\n방별 결과 (성공 시간/이동):\n")
    w("| 방 | " + " | ".join(c for c, _ in CONDS) + " | 41방 평가(참고) |\n|---|" + "---|" * (len(CONDS) + 1))
    for room in ROOMS:
        w(f"| {room} | " + " | ".join(cell(data[c].get(room)) for c, _ in CONDS) + f" | {cell(full1.get(room))} |")
    w("")
    w("## 5. 해석과 한계 (중요)\n")
    w("* **표본이 작다**: 방 8개, 조건당 1회. 성공률 차이는 우연과 변동이 섞였을 수 있다. 성공 시간도 방마다 편차가 크다.")
    w("* 신뢰 격자는 규칙 기반이 놓친 방(3012, 3013, 3031)을 찾았다. 반면 규칙 기반이 아주 빠르게 찾은 방(3022, 3040)에서는 신뢰 격자가 느렸다. 즉 신뢰 격자는 안정적이고 규칙은 운이 좋으면 빠르다.")
    w("* **ReasonNav(D)**: 찾은 방에서는 가장 빠르고 이동이 짧았다(성공 5개의 시간 중앙값 352초, 평균 이동 137 m). 3031은 334초/67 m로 모든 조건 중 가장 빨랐다. 반면 서쪽 방 3010·3012·3013을 모두 못 찾아 성공률은 규칙 기반과 같은 5/8이다. 서쪽 실패의 원인은 확인하지 않았다(3010은 로봇이 정답에서 65 m 떨어진 곳에 있었음).")
    w("* 안내판을 신뢰 격자에 더한 효과는 이 표본에서는 분명하지 않다(성공률 같고 시간은 방마다 늘고 줄었다).")
    w("* **ReasonNav(D)와의 비교는 완전히 같은 조건이 아니다**: ReasonNav의 판단(어느 랜드마크로 갈지: VLM이 지도와 안내판 사진을 보고 고름)은 그대로 쓰고, 검출·번호 읽기·안내판 해석은 우리 파이프라인 결과를 `vlm_nav`의 랜드마크 DB에 넣어 주었다. 다만 (1) ReasonNav는 자기 VLM 설정(gpt-5.4-mini 선택, gpt-5.4 OCR)을 쓴다, (2) 우리 읽기는 최대 10 m에서 읽지만 ReasonNav에는 8 m 안의 번호표만 넣고 3.5 m 안에서 발견을 선언한다(자체 규칙에 맞춤), (3) 안내판 방향은 4방향(위/아래/좌/우)으로 변환되어 사선 방향은 '없음'이 된다.")
    w("* 앞 단계에서 ReasonNav를 자체 검출기(OWL-ViT)로 돌리려던 시도는 해결하지 못했다(검출 결과가 비어 문 랜드마크가 생기지 않음, 카메라 해상도를 1280×960으로 낮춰도 번호판이 56 px라 읽기 실패). 그래서 OWL-ViT 대 YOLO 검출 비교는 하지 못했다.")
    w("* 4K는 영상 전송이 느려(프레임 속도 카메라당 1.6 → 0.7장/초) 처리 속도가 떨어진다. 우리 파이프라인은 카메라별 최신 프레임만 쓰는 구조라 견딘다.")
    w("* 신뢰 격자의 LLM 방향 예측은 약하다(정답 방향 45° 이내 61~71%). 같은 번호판 목록에 대해 예측이 흔들리기도 했다. 누적·감쇠와 '본 곳 리셋'이 이를 보완한다.")
    w("* 번호가 한 방향으로만 늘지 않는다(복도 양쪽·U자 배치). 이를 모르는 직선 외삽은 반대 방향을 가리켰다 → 번호 보간은 두 번호 사이에서만 쓰도록 고쳤다.\n")
    w("## 6. 검출 현황 (41방 평가 기록 기준)\n")
    w("* **문**: YOLO 문 모델(doordetect_oi) + 실제 크기 필터(폭 0.45~2.4 m, 높이 1.4~2.9 m). 정답이 없어 정밀도·재현율은 측정하지 못함. 실행당 등록 중앙값 50개, 71%가 번호판 3 m 안.")
    w("* **번호판**: VLM 읽기 7361건 중 66%가 null. 숫자를 돌려준 건 중 80%가 실제 방 번호. 거리별 정답(위치까지 맞음): 3 m 안 83%, 3~6 m 72%, 6 m 이상 62%. 확정 라벨 300개 중 99%가 실제 번호, 95%가 맞는 위치.")
    w("* **방향 안내판**: 진짜 안내판 4개 중 examination·waiting은 자주 읽히나 public service·consultation은 드물다(서쪽). 해석된 방향의 84%가 정답 방향 60° 이내. 등록된 안내판의 73%는 안내판이 아닌 것(명패 등).\n")
    w("## 7. 만든 것과 위치\n")
    w("* 방 찾기: `tips_ws/.../mm_dev/nodes/room_perception.py`, `room_finder.py`, `room_recorder.py`; `mm_dev/room_finder/{vlm,decide,belief,viz,camera_rig}.py`")
    w("* 실행/평가: `scripts/reasonnav_sim/{run_reasonnav_sim.sh, run_trials.py, run_policy_matrix.sh, eval_summary.py, rn_adapter.py, rn_vlmnav_ours.py, rn_detector_swap.py}`, `tools/{vlm_bench.py, decision_eval.py, policy_report.py, rerender_video.py, make_report.py}`")
    w("* 결과: `log/reasonnav_sim/full_eval/full1/`(41방), `full_eval/pm1_<조건>/videos/`(정책 비교 영상), `trials/*.jsonl`, `trials/pm1_*.jsonl`, `log/reasonnav_sim/vlm_bench/bench1.json`")
    w("* 실행 예: `python3 scripts/reasonnav_sim/run_trials.py 3022 --record --env \"POLICY=belief BELIEF_SIGNS=both\"`, ReasonNav: `--extra=\"--rn --rn-det inject\"`\n")
    w("## 8. 남은 일 / 제안\n")
    w("* 표본을 늘려(방 수·반복) 정책 간 차이가 실제인지 확인. 특히 신뢰 격자 vs 규칙 기반, 안내판 효과.")
    w("* 3010처럼 화장실에 갇히는 경우의 복구 동작(안전 지점으로 후퇴)과 목표 지점의 장애물 거리 제한.")
    w("* 로봇이 번호판에서 멀리(3~4 m) 멈추는 문제(도착 거리 설정).")
    w("* ReasonNav 원본 검출기(OWL-ViT)와의 비교: 검출기가 시뮬레이션 영상에서 문을 못 잡는 원인(임계값·해상도) 파악 필요.\n")
    os.makedirs(f"{WS}/log/reasonnav_sim/full_eval", exist_ok=True)
    open(f"{WS}/log/reasonnav_sim/full_eval/REPORT.md", "w").write("\n".join(out) + "\n")
    print("written", f"{WS}/log/reasonnav_sim/full_eval/REPORT.md")


if __name__ == "__main__":
    main()
