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
  ~/room_finder_venv/bin/python robot_pc/robot_gateway.py --robot-id KR-RND-2508-001 --iface enxc84d442343c1 --map-bounds -60 -60 60 60 \
  --transient-s 8
# AI PC: GDINO (TensorRT, 960x720 engine for the 4:3 IMX378 frames), then the finder
HF_HUB_OFFLINE=1 ~/room_finder_venv/bin/python <ws>/scripts/room_finder_net/ai_pc/gdino_trt/gdino_server_trt.py --engine ~/gdino_trt/gdino_fp16.engine
cd <ws>/scripts/room_finder_net && source <ws>/ld_prefix_path.sh && \
  RF_PARAMS=room_finder.belief_sign_steer=true,room_finder.sign_seek=100,room_finder.sign_lock=true,room_finder.agree_gain=2.5,room_finder.agree_stall_s=90,room_finder.sign_passed_m=5 \
  ROOM_FINDER_VLM=gpt-5.4-mini ROOM_FINDER_BELIEF_VLM=gpt-5-mini \
  ~/room_finder_venv/bin/python ai_pc/ai_main.py --target T113 --robot-id KR-RND-2508-001 --iface enP5p3s0 \
  --cameras local --rig ai_pc/rig_real.yaml --mmdev ~/ReasonNav/src/mm_dev
```
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
| `GOAL_UNLOOKED=1` | a VLM goal inside the looked-at area is moved on along robot -> goal |
| `BELIEF_CONSENSUS=4` | a VLM goal is weighted by how many of the last 4 answers agree (one flipped answer does not switch wings) |
| `BELIEF_OPENINGS=1` | lettered frontier openings on the VLM map; a `via` opening is used only if it leads toward the goal |
| gateway `--dynamic-cap 1.5 --dynamic-clear-s 3` | cells seen free before (people walking by) clear after 3 s without hits |
| gateway `--transient-s 8` (flag) | cells never seen free and hit for < 8 s go back to unknown 15 s after their last hit (a person in an unexplored corridor); a wall glimpsed < 8 s does too |
| `RF_PARAMS` agree_gain / agree_stall_s / sign_passed_m | the dev-PC sim "all" variant: a VLM goal along the target sign's arrow is followed (frontiers +2.5 per m closer, dropped after 90 s without 3 m progress); a sign passed by 5 m no longer locks |

Each run also writes `camera_exposure.jsonl` (exposure / ISO / grey per colour frame). Known open issues: the robot sometimes stands
still with a goal (navigation plugin "Start occupied", SLAM odometry dropouts, or no logged reason); the VLM reads the T101~T126 arrow
literally (north) until plates of that hallway are read.

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
