# ReasonNav on the raisin hospital simulation

One command brings up the raisin sim, the raisin_network <-> ROS 2 bridge, the glue that makes
raisin look like nav2 to ReasonNav, and ReasonNav's own nodes:

```bash
scripts/reasonnav_sim/run_reasonnav_sim.sh            # everything: sim, gui, bridge, glue, detector, bringup, vlm_nav
scripts/reasonnav_sim/run_reasonnav_sim.sh --no-gui --no-vlm   # opt-outs: --no-gui --no-bringup --no-vlm
scripts/reasonnav_sim/run_reasonnav_sim.sh --kill
```

Everything runs in a tmux session `reasonnav_sim`; each window tees its output to
`log/reasonnav_sim/<timestamp>/`. `--goal <room>` sets the target room for vlm_nav (`REASONNAV_GOAL`,
else `task.goal` in `mm_dev/config/vlm_nav_config.yaml`).

RViz (`reasonnav_sim.rviz`, derived from ReasonNav's `handheld.rviz`, fixed frame `map`) shows: the
detector's annotated image (`/object_detector/output_image`), the landmark/frontier map image
(`/frontier_image`), frontier markers (`/frontiers`), the VLM goal marker (`/goal_marker`), the costmap
(`/global_costmap/costmap`), raisin's costmap/plan point clouds (`/navigation/vis/*`), lidar_slam's
`/cloud_registered`, `/odom`, TF and the raw camera (`/d455_front/rgb`). Skip it with `--no-rviz`.

## Bringing the robot up from ROS (no GUI needed)

```bash
scripts/reasonnav_sim/bringup.sh      # run automatically by the launcher unless --no-bringup is given
```

`bringup.sh` walks the bridged raisin services in the order the GUI uses: `/turn_on` →
`/transition_to_state {data: blind_locomotion}` (state chain: init_motor → joint_test → stand_up →
load_controller; a joint-test diagnostic warning is confirmed via `/confirm_state_chain` within its 10 s
window) → `/set_listen {data: vel_cmd/autonomy}` (the robot follows the navigation plugin's velocity
output) → `/start_mapping` (lidar_slam idles until then and navigation has no `/Odometry/base` without it).
After that a nav2 goal moves the robot; verified 2026-09-23 with a 3 m goal (`SUCCEEDED`, raisin
`All waypoints completed!`).

Frames: raisin navigation plans in a frame named after the robot's network id (e.g. `mun_raibo-4080686931`),
which is the `frame_id` of `/Odometry/base`. The glue uses that odometry for `map -> odom -> base_link`
and stamps waypoints with that frame (`waypoint_frame: auto`).

## Data flow

```
ReasonNav (ROS 2)                     glue (raisin_nav_glue.py)              raisin_bridge          raisin sim
navigate_to_pose / spin  ── action ──►  SetWaypoints client  ── /planning/set_waypoints ──► navigation plugin
/global_costmap/costmap  ◄─ rasterize ─  /navigation/vis/global_costmap (PointCloud2) ◄────  navigation plugin relay
/tf map->odom->base_link ◄─────────────  /Odometry/base  ◄──────────────────────────────────  lidar_slam
/camera/*/camera_info    ◄─ synthesized (d455 FOV from realsense455.xml)
/camera/color/image_raw  ◄─ remap ───────────────────────── /d455_front/rgb  ◄─────────────  d455_front plugin
/camera/depth/image_rect_raw ◄─ remap ────────────────────── /d455_front/depth ◄────────────  (32FC1 metres)
```

* Velocity commands are **not** bridged. ReasonNav only decides *where* to go; raisin's navigation
  plugin (planner + MPPI controller, `vel_cmd/autonomy`) drives the robot.
* `bridge_params.yaml.in` lists the bridged topics/services; `@PEER_ID@` becomes the sim node's
  `robot_nickname` (read from `~/.raisin/raisin_raibo2/params.yaml`, else the package params).
* ReasonNav's nodes are started with `use_sim_time:=false` because raisin publishes no `/clock`.

## Prerequisites

* raisin built **and installed** (`ninja -C cmake-build-release install`) — raisin_bridge needs
  `install/include/raisin_network` and `install/lib/cmake/raisin_network`.
* raisin_bridge_ws built with the conversions used here:
  `colcon build --packages-select raisin_bridge raisin_interfaces raisin_interfaces_conversion sensor_msgs_conversion nav_msgs_conversion --cmake-args -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$RAISIN_WS/install`
* `install/config/raisin_raibo2/config/params.yaml`: `raisim_config: /raisim_config/hospital.xml` and
  `navigation` in the `plugin:` start-up list (it brings `lidar_slam` and `grid_mapping` with it), so
  `/planning/set_waypoints` exists as soon as the robot is turned on.
* ReasonNav (`tips_ws`) built natively. Its nodes run on the host (docker is not used): the detector
  falls back from NanoOWL to PyTorch OWL-ViT (`REASONNAV_DETECTOR=owlvit`, torch+CUDA present), and
  `vlm_nav.py` needs `pip install openai python-dotenv` plus the OpenAI/Bing keys in
  `src/mm_dev/config/.env`. The launcher warns about missing modules at start.

## ReasonNav host environment (checked 2026-09-23)

The native `tips_ws` build is what `ros2 run mm_dev ...` uses here. Fixes applied on 2026-09-23:

* `vlm_nav.py` imports `landmark_handlers` from its own directory, but `mm_dev/CMakeLists.txt` did not
  install `nodes/landmark_handlers.py`; it was added to the `install(PROGRAMS ...)` list and `tips_ws`
  rebuilt (`colcon build`, copy install — the existing tree was not a symlink install).
* `vision_msgs` (detector): built from source in `tips_ws/src/vision_msgs` (humble branch, rviz plugin
  ignored) because apt needs sudo.
* `openai` **1.x** (`pip install --user "openai<2"`; 3.x bundles `httpx2`, whose decompressor fails with
  `TypeError: process() takes no keyword arguments` on this host), `python-dotenv`, `pyrealsense2`.
* OpenAI key: `vlm_nav` prefers an exported `OPENAI_API_KEY` over `mm_dev/config/.env`; the one exported in
  `~/.bashrc` was stale (401), so the launcher unsets it for the vlm_nav window (set `REASONNAV_USE_ENV_KEY=1`
  to keep the shell value). Put the key in `tips_ws/src/ReasonNav/src/mm_dev/config/.env` (the installed copy
  `install/mm_dev/share/mm_dev/config/.env` is what the running node reads; rebuild or edit both).
* User-level `numpy` was 2.2.6, which breaks humble's `cv_bridge` (`_ARRAY_API not found`); downgraded to
  `numpy<2` (1.26.4). torch 2.9 / transformers 4.38 / open3d / opencv-python 4.12 still import fine.
* User-level `numba` needed `coverage>=7` (`coverage.types`); upgraded `coverage` with `pip install --user -U`.
* `fast_lio` in `tips_ws` fails to configure and is skipped (`--continue-on-error`); the previous install of it
  is untouched and it is not needed here (raisin does the SLAM).
* Verified: `ros2 run mm_dev detector.py` loads the OWL-ViT backend; `ros2 run mm_dev vlm_nav.py` starts
  and waits for the `map` frame (provided by the glue).
* Alternatively run those two nodes in ReasonNav's docker container with `--docker`
  (the launcher then uses `docker compose run --rm ros2_pc ...`; the user needs docker access and the
  image `mm_system/humble`, and the repo-mounted `install/` must be built inside the container).

## Known gaps / next steps

* `waypoint_frame` is `odom` and the glue publishes `map -> odom` as identity, i.e. ReasonNav's `map`
  is raisin's state-estimator frame. Fine for a single run; there is no loop-closure-corrected map.
* `/global_costmap/costmap`: obstacles come from the `navigation/vis/global_costmap` point cloud (colour = cost
  class: lethal 100 / inscribed 99 / high inflation 60 / low 30) kept in a persistent grid over `map_bounds`;
  raisin tracks no unknown space, so the glue ray-casts from the robot pose (`sensing_range`, `ray_count`) and
  only cells a clear ray reached are published as known — the rest stay -1, which gives ReasonNav real frontiers.
* Spin is emulated with yaw-only waypoints at the current position: raisin navigation aligns heading for
  `use_yaw` waypoints (SmacPlanner goal heading + MPPI `GoalAngleCritic`), and the goal checker's
  `yaw_goal_tolerance` was lowered from 6.28 to 0.4 in `raisin_navigation_plugin/config/params.yaml`
  (src + install) so such waypoints only complete once aligned. Verified: 1.57 rad request -> 1.42 rad.
* `/joint_states` and the pan-tilt commands ReasonNav uses on its own robot are not provided.
* The navigation plugin runs as a separate process; its own topics (`navigation/status`, `navigation/global_costmap`,
  `navigation/global_plan`) are not visible to the bridge, only the `navigation/vis/*` relays in the main node.
  Goal completion is therefore judged from distance/yaw tolerance (`goal_tolerance`, `yaw_tolerance`).

## Room finder (3 cameras + door/plate/sign perception) — added 2026-09-30

This replaces the single-camera ReasonNav detector flow as the default (`--legacy` still starts the old one).

Sensors: three simulated OAK-D Pro W on the `oak_mast` module (front / left / right, 90° apart, 1.113 m above the
torso origin, i.e. ~1 m above the top plate). Colour 1280x960, depth 640x480 (z-depth, m), 6 Hz. The glue publishes
static TF `base_link -> oak_front|oak_left|oak_right` and `livox_frame`.

Nodes (run from source in `tips_ws/src/ReasonNav/src/mm_dev`):

| node | what it does |
| --- | --- |
| `gdino_server.py` | Grounding DINO HTTP server (`.venv_autolabel`), finds signs and plates |
| `room_perception.py` | door YOLO (`yolo_ws/runs/doordetect_oi/weights/best.pt`) + physical size filter; 3D-masked crop around the door -> gpt-4.1 reads the number (label accepted after >=2 concordant reads, closer reads weigh more); signs: GDINO -> plane fit for the normal -> gpt-4.1 parses (place, direction) tuples as in "Sign Language" -> bearing = view_yaw + offset; cues are merged across reads |
| `room_finder.py` | lidar log-odds occupancy map, frontier + door + sign + verify candidates, hints from sign rays / plate-number interpolation / west->east number prior, hysteresis, carrot goals to `/room_finder/goal`; writes `finder/result.json` |

Run: `run_reasonnav_sim.sh --goal 3018` (one window each: gdino, perception, finder). Trials from a clean start, scored
against `gt/hospital_rooms.json`: `python3 run_trials.py 3005 3030 3022 --max-time 1200 --tag foo`
-> `log/reasonnav_sim/trials/foo.jsonl` (success = claimed label within 3 m of the GT plate and robot within 4 m).
The harness waits for the previous sim to exit fully and retries a trial whose robot never moved (SLAM/bring-up race).

Known weaknesses: far-side rooms still cost 10–20 min; the sign parse is view dependent (a wrong early read can send
the robot the wrong way); plates are only readable within ~3 m; the numbering prior (numbers grow west->east) is
specific to this building.
