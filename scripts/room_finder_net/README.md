# room_finder_net — room finder on two PCs, raisin_network only (no ROS 2)

```
 robot PC                                              AI PC
 ┌──────────────────────────────┐   raisin_network   ┌────────────────────────────────────┐
 │ raisin (navigation, lidar_slam,│ ───────────────► │ ai_pc/ai_main.py                    │
 │ OAK cameras)                  │  oak_*/rgb|depth   │  room_perception (YOLO door, plate/ │
 │                               │  /Odometry/base    │  sign VLM, OCR, Grounding DINO)     │
 │ robot_pc/robot_gateway.py     │ ───────────────► │  room_finder (belief policy, VLM)   │
 │  · map from cloud_registered  │  room_finder/map   │                                    │
 │  · goal → planning/set_waypoints ◄──────────────── │  goal = service room_finder/goal    │
 │  · watchdog, goal checks      │                    └────────────────────────────────────┘
 └──────────────────────────────┘
```

* `raisin_py/` – pybind11 binding of `raisin_network` (C++). Nothing else in this directory needs ROS.
* `robot_pc/robot_gateway.py` – runs next to the robot's raisin node: goal point → raisin navigation, occupancy grid
  (unknown = −1) built from `cloud_registered`, status, **watchdog** (no goal for 10 s ⇒ goal cancelled), goal sanity check
  (finite, ≤ 8 m from the robot).
* `ai_pc/ai_main.py` – runs ReasonNav's `room_perception.py` + `room_finder.py` **unchanged**. `ai_pc/rosless.py` supplies
  stand-ins for the handful of `rclpy` / message / `tf2_ros` names those files import and routes their topics:
  images and odometry come from the robot, the map and goal go through the gateway, everything else stays in-process.
  `ai_pc/rig.yaml` = camera mount (height, yaw, intrinsics) — **edit for the real robot**.
* `ai_pc/bringup_sim.py`, `run_net_sim.sh` – simulation only: stand the simulated raibo up and start everything on one machine.

## Build the binding (once per machine that has a raisin install tree)
```
pip install --user pybind11
cd raisin_py && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$RAISIN_WS/install \
      -Dpybind11_DIR=$(python3 -c "import pybind11;print(pybind11.get_cmake_dir())") && cmake --build build -j
```
Run with `source $RAISIN_WS/ld_prefix_path.sh` (library path) — the scripts find `raisin_py/build` themselves.

## Robot PC
```
source $RAISIN_WS/ld_prefix_path.sh
python3 robot_pc/robot_gateway.py --robot-id <robot_nickname> --iface <net interface to the AI PC>
```
Robot up (stand, `vel_cmd/autonomy` listen, `start_mapping`) as usual from the GUI. `--map-bounds` sets the mapped area.

## AI PC
Needs: this repo's ai_pc + ReasonNav's `mm_dev` (`--mmdev`), the raisin install tree (for `libraisin_network`),
`pip install ultralytics openai python-dotenv opencv-python scikit-image scipy pyyaml pytesseract`, `tesseract-ocr`, an OpenAI key
(`mm_dev/config/.env`, or `--env-key` to use `$OPENAI_API_KEY`), and the Grounding DINO server
(`room_finder_assets/run_gdino.sh` in ReasonNav).
```
source $RAISIN_WS/ld_prefix_path.sh
BELIEF_SIGNS=vlm POLICY=belief python3 ai_pc/ai_main.py --target 3018 --robot-id <robot_nickname> \
      --gateway-id room_finder_gw --iface <net interface to the robot>
```
Both PCs must be on the same network segment (raisin discovery is multicast) with each other's ids resolvable.

## AI PC with the cameras attached directly (real robot) and no internet
```
ai_pc/deploy_to_ai_pc.sh user@ai-pc            # on a machine with internet: offline wheelhouse (Jetson torch, aarch64 wheels) + code + GDINO weights -> AI PC
bash ~/room_finder_deploy/raisin_ws_scripts/room_finder_net/ai_pc/setup_ai_pc.sh      # on the AI PC: venv ~/room_finder_venv, raisin_py build
```
Run (AI PC):
```
HF_HUB_OFFLINE=1 GDINO_VENV=~/room_finder_venv ~/room_finder_deploy/ReasonNav/room_finder_assets/run_gdino.sh &      # Grounding DINO server
~/room_finder_venv/bin/python ai_pc/ai_main.py --target 3018 --robot-id <robot_nickname> --iface <if> \
      --cameras local --rig ai_pc/rig_real.yaml --mmdev ~/room_finder_deploy/ReasonNav/src/mm_dev --dummy-vlm
```
* `--cameras local`: the OAK-D Pro W cameras listed with an `ip` in the rig file are opened with depthai (colour JPEG-encoded on the camera,
  depth = on-camera StereoDepth aligned to the colour sensor, float32 m); odometry and the map still come from the robot over raisin_network.
  Frames are stamped 0 (latest odometry pose is used) unless `--stamp-host` and the two clocks are synchronised.
* `--dummy-vlm`: no OpenAI call. Plate reads answer "no plate", sign reads "no cues", belief queries "no region": the finder explores
  frontiers and detects doors / signs, but cannot confirm a room number (no success without a VLM or another number reader).

## Real robot runs (Raibo2, KR-RND-2508-001, as of 2026-11-04)
The defaults in `ai_main.py` / `rig_real.yaml` are the real-robot settings; nothing needs to be set for a normal run. Run from the
workspace that holds these scripts (logs go to `<workspace>/log/room_finder_net/<time>_T<target>/`).
```
# robot PC (after standing the robot up and starting mapping)
cd <ws>/scripts/room_finder_net && source <ws>/ld_prefix_path.sh && \
  ~/room_finder_venv/bin/python robot_pc/robot_gateway.py --robot-id KR-RND-2508-001 --iface enxc84d442343c1 --map-bounds -100 -100 100 100 \
  --map-res 0.05 --inflate 0.4 --transient-s 8 --log-dir
# AI PC: GDINO (TensorRT, 960x720 engine for the 4:3 IMX378 frames) and the OCR server in one shell (Ctrl+C stops both), then the
# finder in another one. ai_main waits until both servers answer.
bash -c 'trap "kill 0" EXIT; HF_HUB_OFFLINE=1 ~/room_finder_venv/bin/python <ws>/scripts/room_finder_net/ai_pc/gdino_trt/gdino_server_trt.py --engine ~/gdino_trt/gdino_fp16.engine & ~/ocr_venv/bin/python <ws>/scripts/room_finder_net/ai_pc/ocr_server.py & wait'
cd <ws>/scripts/room_finder_net && source <ws>/ld_prefix_path.sh && \
  RF_PARAMS=room_finder.belief_sign_steer=true,room_finder.sign_seek=100,room_finder.sign_lock=true \
  ROOM_FINDER_VLM=gpt-5.4-mini ROOM_FINDER_BELIEF_VLM=gpt-5-mini \
  ~/room_finder_venv/bin/python ai_pc/ai_main.py --target T113 --robot-id KR-RND-2508-001 --iface enP5p3s0 \
  --cameras local --rig ai_pc/rig_real.yaml --mmdev ~/ReasonNav/src/mm_dev --log-debug-hz 2
```
Logs of what the two viewers show (for videos):
* gateway `--log-dir` (http://<robot PC>:8081): `<robot PC ws>/log/room_finder_net/gateway/<start time>/state.jsonl` (pose, goal and
  the AI PC's landmarks + finder state, 2 Hz) and `map/<time ms>.npz` (the published grid, every 2 s). One folder per gateway start,
  robot PC clock. `viz.looked` in it (every 2 s) holds the finder's looked-at cells (zlib + packbits, row 0 = lowest y); the viewer does
  not draw them.
* ai_main `--log-debug-hz 2` (http://<AI PC>:8082): `<run>/debug_image/<time ms>.jpg` + `frames.csv` with the AI PC time and the robot
  PC time (the AI PC clock is not NTP-synced; it was 55.8 s ahead on 11-10), so the two logs line up.
* Video from both (`ai_pc/render_video.py`, on the AI PC: it has ffmpeg with H.264). Copy the gateway folder over, then render
  (8081 map + panel above, 8082 cameras below, 1920x1080, x8, ends 8 s after the finder is done; ~2.5 min for a 10 min run):
  ```
  scp -r ~/raisin_ws/log/room_finder_net/gateway/<time> raibonav@192.168.1.77:raisin_ws/log/room_finder_net/gateway/   # robot PC
  cd ~/raisin_ws/scripts/room_finder_net && L=~/raisin_ws/log/room_finder_net && \
    ~/room_finder_venv/bin/python ai_pc/render_video.py --gw $L/gateway/<time> --run $L/<time>_T<target>      # -> <run>/video.mp4
  ```
  `--layout map` / `cams` for one view, `--view follow` to follow the robot, `--speed`, `--from` / `--to` (s), `--still end --out map.png`
  for one picture (the robot PC's python3 can render stills: no ffmpeg needed).
Before a run:
* The AI PC needs internet (LTE): every plate / sign read and belief query is an OpenAI call. Check with `ping 8.8.8.8`.
* The AI PC needs a gigabit link to the PoE switch: three 12 MP cameras use ~470 Mbit/s.
* raisin::Network versions must match: robot node, gateway `raisin_py`, AI PC `raisin_py`
  (`install/include/raisin_network/network.hpp`, `version_`). The robot PC's `raisin_ota_agent` installs releases into `~/raisin_ws`
  and restarts the robot service. After an update, install the same release on the AI PC
  (`python3 raisin.py -y install --all --archive-version <ver>`, then rebuild `install/` from `release/versions/<gen>`) and rebuild
  `raisin_py` on both PCs.

What was changed for the real building (env variable in `ai_main.py` = ReasonNav parameter, all default on here, off in the sim):
| env (default) | what |
|---|---|
| `GDINO_HZ=0 GDINO_WORKERS=2 GDINO_WIDTH=960` | GDINO without wait, 2 requests in flight: ~1.1 Hz per camera with the YOLO TensorRT engine |
| `DARK_ENHANCE=70` | luma stretch + CLAHE for dark crops before the VLM |
| `SIGN_OCR_WORDS=0` | Tesseract gate off (it rejected 32 of 33 real signs) |
| `SIGN_OVERWRITE=1` | a later comparable sign read replaces unconfirmed (misread) entries |
| `DET_REACH_M=1.5` | doors / signs > 1.5 m off the traversable area are dropped; room plates never are |
| `FRONTIER_ON_FREE=1` | frontiers from free cells: narrow corridor ends (2 m, inflated walls) still count |
| `GOAL_UNLOOKED=1` | a VLM goal inside the looked-at area is ignored (moving it on sent it into the wrong wing) |
| `BELIEF_CONSENSUS=4` | a VLM goal is weighted by how many of the last 4 answers agree (one flipped answer does not switch wings) |
| `BELIEF_OPENINGS=1` | lettered frontier openings on the VLM map; a `via` opening is used only if it leads toward the goal |
| `VISIT_SIGNS=1 VISIT_DOORS=1 VISIT_MAX_PC=4 VISIT_NO_BACK=1 VISIT_LABELS=0` | signs / doors are visited only when the path there is <= 4 m and not behind the direction of travel (unlimited visits: back and forth in the lobby; none: the lobby signs stayed unread). Plates one digit off the target are not visited; a read of the target is |
| `LOOK_STOP_S=1.5 LOOK_STOP_M=2.5` | stand still 1.5 s next to an unread door / plate / sign within 2.5 m, once each (the waypoints have no speed limit, so stopping is the "slow down") |
| `LOOK_RADIUS=3 LOOK_FAR=6 LOOK_OPEN_M=1.5` | "looked at" = within 3 m of the path (through walls) plus 6 m in line of sight where it is >= 2 m from walls (the lobby). A 5 m line of sight everywhere (11-10 17:17) dismissed the right VLM goal 4 m away before its plate was read and never covered the cells under the walls' inflation |
| `SIGN_CORRIDOR=1 SIGN_NEG_PENALTY=40` | a sign arrow pointing at a corridor mouth 1-4 m away means that corridor (it runs across the arrow): 'T101~T126' at (-11, -1) -> west, 'T131~T150' at (6, -1) -> east. Candidates in the corridor of an entry without the target lose 40 points (17:17: 'T131~T150' read at 17 s, the robot still drove to the east corridor's end) |
| `SIGN_BROAD_W=1` | the most specific sign entry listing the target gets the full belief weight (4), broader ones 1 (18:08: 'T112~T126' south outweighed 'T112~T121' west at T112) |
| `SOFT_WEIGHT=1.5` | path cost per cell 1 + 1.5 x (0.9 m - clearance), was 6: a 2 m corridor cost ~4.5x its length, so the frontier 4.5 m down the T112 corridor lost to one 12 m away in a hall |
| `SIGN_CROP_MX=0.3` + bent arrows | signs are cropped with 30 % of the box width left / right (GDINO cut the bent arrow of 'T112~T121' in half). The sign prompt knows bent arrows (`left-then-straight`, `right-then-straight`, `straight-then-left`, `straight-then-right`): the route follows the first leg from where a reader stands and turns at the first >= 2.5 m opening toward the second leg. The viewer draws them with two legs |
| `GDINO_PLATES=0` | GDINO plate boxes are no longer read by the VLM (OCR + door crops only; see the OCR server section) |
| `OCR_VERIFY=1` + plate prompt | an OCR room number counts only after the VLM, shown the frame around it (the text boxed in red, >= 3 box widths each side; the OCR's text is not in the prompt), reads the same digits (one off allowed) and calls it a room plate: one check per number and place, reads wait for it, a no drops them. 11-10: '2026' on a poster at the start and the 0119 of an emergency phone sticker (042-350-0119) became rooms. The plate prompt of the door / GDINO path names phone / emergency numbers, years, stickers and posters as non-plates (the sticker was read as 0119 5 of 5 times before, 0 of 5 after). Debug image: white `T113 ?` = waiting, grey `2026 x` = rejected; `crops/ocrv_*.jpg` + `ocr_verify` events |
| `TRAV_OCC_M=0.57` `FINDER_GRID_RES=0.1` + gateway `--map-res 0.05` (`--subcell 1` is the default) | passages: 1.10 / 1.12 m blocked, 1.2 m traversable at any wall angle (11-11). The gateway keeps where inside each 5 cm cell the lidar points hit (running mean, published as the obstacle value 101..125 = 1 cm steps; 100 = no position) and the finder measures a passage from those positions: traversable = a point of the cell >= 0.57 m from every hit (`passage_trav`: exact clearance at the cell centre plus the ridge towards the neighbour away from the nearest hit), then the map is folded into 10 cm cells for everything else. Why: with cell centres only, a wall is known to the cell; the 1.12 m passage at (-7.0, -2.7) read 1.10 m between cell centres and 0.525 let it in (11-11 14:00), while a 1.2 m corridor a degree off the grid steps to 1.15 m where its wall crosses a cell row, so no threshold did both. Simulated through the gateway's own code (on_cloud / publish_map) over angles 0-45 deg and grid offsets: 1.10 / 1.12 m pass 0 %, 1.2 / 1.25 m 100 % with 0-1 cm wall noise; with 2 cm noise 1.2 m mostly fails (the walls read narrower), 1.25 m passes. Without hit positions the finder uses 0.575 on 5 cm (1.2 m passes, 1.12 m may) or 0.5 on 10 cm and warns. Cost: the finder ~130 ms per 5 cm map, the gateway ~60 ms more per map. The 11-10 runs had the gateway at `--inflate 0.5`, so TRAV_CLEAR=0.1 passed ~1.3 m, not 1.0 m. The robot's own navigation still checks its footprint |
| `VIEWPOINT_FALLBACK_M=2.5` | no free spot 1-2 m in front of a plate (2 m corridor): the nearest traversable cell within 2.5 m. 18:08: T113 was read once by the OCR, and re-reading it never became a candidate |
| `RELOOK=1` | VLM goals ignored as already looked at are re-checked once (low score, 3 s look) before giving up. 18:08: the VLM named T113's spot 7 times; the robot gave up 6 m away |
| ai_main start | waits (with an error line every 10 s) until the GDINO and OCR servers accept connections (17:17 ran without the OCR server) |
| `FRONTIER_MIN_DIST=1.5` | a frontier's goal point is its cheapest cell >= 1.5 m away. A corridor's frontier starts at the robot, and its nearest cell (< 0.8 m) used to drop the whole frontier (11-10 T113: turned back out of the west corridor) |
| gateway `--dynamic-cap 1.5 --dynamic-clear-s 3` | cells seen free before (people walking by) clear after 3 s without hits |
| gateway `--transient-s 8` (flag) | cells never seen free and hit for < 8 s go back to unknown 15 s after their last hit (a person in an unexplored corridor); a wall glimpsed < 8 s does too |
| `RF_PARAMS` agree_gain / agree_stall_s / sign_passed_m (not used) | the dev-PC sim "all" variant. Off on the robot since 11-10: the T101~T126 arrow points at an entrance 2 m away with the hallway running perpendicular, the VLM reads it literally, and "agreement" pulled the robot out of the right hallway twice |

Each run also writes `camera_exposure.jsonl` (exposure / ISO / grey per colour frame). Known open issues: the robot sometimes stands
still with a goal (navigation plugin "Start occupied", SLAM odometry dropouts, or no logged reason); the VLM reads the T101~T126 arrow
literally (north) until plates of that hallway are read.

### OCR server (room plates)
`ai_pc/ocr_server.py` runs RapidOCR (PP-OCRv4) on the GPU in its own venv, kept apart from the perception venv:
```
python3 -m venv ~/ocr_venv && ~/ocr_venv/bin/pip install rapidocr_onnxruntime opencv-python-headless
~/ocr_venv/bin/pip uninstall -y onnxruntime && ~/ocr_venv/bin/pip install onnxruntime-gpu --index-url https://pypi.jetson-ai-lab.io/jp6/cu126
```
`room_perception` sends each camera's newest frame to it in turn (`OCR_URL`, default `http://127.0.0.1:8767`).
* Texts shaped like a room number (`T104`; `O`/`I`/`L` in the digits read as `0`/`1`) at conf >= 0.9 become plate reads at the depth
  inside the text box.
* A bare number is dropped while the plates read so far carry a letter prefix: the OCR sometimes reads `T117` as `1117`.
* `OCR_VERIFY=1` (default): each new number / place is checked once by the VLM on the frame around it (table above).
* On the 11-10 hand-driven recording it found all 16 plates T101..T117 the robot passed, ~330 ms per 12 MP frame.
* GDINO plate boxes no longer go to the VLM (`GDINO_PLATES=0`, since 11-11; `1` turns that path back on). In the 11-10 runs it made
  189-414 VLM calls a run for 5-13 reads, and every number it read twice that the OCR never read was a misread (0119, 1117, 1116, 121).
  Plates come from the OCR and from the door crops (YOLO door -> VLM); GDINO still finds the signs.

### Recording the cameras (robot driven by hand)
Stop `ai_main` first: only one program can open the cameras. On the AI PC:
```
cd <ws>/scripts/room_finder_net && ~/room_finder_venv/bin/python ai_pc/record_cams.py --hz 1
```
It writes the cameras' 12 MP JPEG frames, unchanged, to `<ws>/log/cam_record/<time>/<cam>/` plus `frames.csv`. Ctrl+C stops it.
`--hz` sets the frames saved per camera per second: 1 Hz is ~7 MB/s for three cameras.

## Simulation check (one machine, no ROS environment)
```
scripts/room_finder_net/run_net_sim.sh --goal 3014      # tmux session room_finder_net; --kill to stop
python3 scripts/reasonnav_sim/run_trials.py --net 3014 3030 --tag net1   # fresh-start trials, same scoring as the ROS runs
```

## Things to know
* Bandwidth: the simulated colour image is 3840×2880 (33 MB per frame, three cameras). Over a real network this needs a wired
  link or a lower camera resolution (plates are readable from ≈30 px; the rig geometry in `rig.yaml` must match the resolution).
* Frames: everything is in the frame of the robot's `/Odometry/base` pose (what raisin navigation plans in); waypoints are sent
  in that frame's id.
* No video recorder in this path (the ROS recorder is not used); `finder.log`, `decisions/`, `perception/crops`, `events.jsonl`
  and `result.json` are written as before.
