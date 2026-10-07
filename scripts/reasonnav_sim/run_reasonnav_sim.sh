#!/usr/bin/env bash
# Launch the whole ReasonNav-on-raisin simulation in one tmux session:
#   raisin    : raisin_raibo2_node in simulation mode (hospital.xml from config/params.yaml)
#   gui       : raisin_gui (3D view + camera streams)            [--no-gui to skip]
#   bridge    : raisin_bridge (raisin_network <-> ROS 2 topics/services)
#   glue      : raisin_nav_glue.py (TF, camera_info, costmap relay, nav2 actions -> raisin waypoints)
#   gdino     : Grounding DINO HTTP server (signs / plates)
#   perception: 3-camera door + room-number + sign perception (room_perception.py)
#   finder    : room finder navigator, target = --goal (room_finder.py)
#   vlm_nav   : ReasonNav VLM navigation (goal = task.goal in mm_dev/config/vlm_nav_config.yaml; needs OpenAI key)
#   rviz      : rviz2 with reasonnav_sim.rviz (detections image, landmark/frontier map, frontier + goal markers, costmap, camera)
#   bringup   : turn_on -> stand up + blind_locomotion -> set_listen vel_cmd/autonomy -> start_mapping (bringup.sh)
#
# Usage: run_reasonnav_sim.sh [--no-gui] [--no-rviz] [--no-bringup] [--no-vlm] [--docker] [--peer <robot_nickname>] [--goal <room>] [--kill]
#        (default = everything: sim, gui, bridge, glue, detector, bringup, vlm_nav)
set -euo pipefail

RAISIN_WS=${RAISIN_WS:-/home/user/raisin_ws}
BRIDGE_WS=${BRIDGE_WS:-/home/user/raisin_bridge_ws}
REASONNAV_WS=${REASONNAV_WS:-/home/user/tips_ws}
ROS_SETUP=${ROS_SETUP:-/opt/ros/humble/setup.bash}
SESSION=${SESSION:-reasonnav_sim}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$RAISIN_WS/log/reasonnav_sim/$(date +%Y%m%d_%H%M%S)"

RN_DET=owlvit; WITH_RN=0; WITH_RECORD=0; WITH_GUI=1; WITH_VLM=1; WITH_DOCKER=0; WITH_BRINGUP=1; WITH_RVIZ=1; WITH_LEGACY=0; WITH_FINDER=1; PEER=""; GOAL="${REASONNAV_GOAL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-gui) WITH_GUI=0 ;;
    --no-rviz) WITH_RVIZ=0 ;;
    --vlm|--bringup) ;;          # kept for compatibility: both are on by default now
    --no-vlm) WITH_VLM=0 ;;      # legacy only: do not start vlm_nav.py
    --legacy) WITH_LEGACY=1 ;;   # also run the original single-camera ReasonNav detector + vlm_nav
    --no-finder) WITH_FINDER=0 ;; # perception only; the room finder (navigator) is started by hand
    --rn-det) RN_DET="$2"; shift ;;      # detection for the --rn stack: owlvit (ReasonNav default) | ours (our boxes only) | inject (our boxes + our plate / sign reading)
    --rn) WITH_RN=1; WITH_FINDER=0 ;;   # run the (modified) ReasonNav vlm_nav + OWL-ViT detector instead of perception/finder
    --record) WITH_RECORD=1 ;;     # save the search as $LOG_DIR/search.mp4 (detections + map + reasoning)
    --no-bringup) WITH_BRINGUP=0 ;;  # do not run bringup.sh (robot stays off; use the GUI or bringup.sh later)
    --docker) WITH_DOCKER=1 ;;   # run ReasonNav nodes in its docker container (ros2_pc) instead of natively
    --peer) PEER="$2"; shift ;;
    --goal) GOAL="$2"; shift ;;   # target room number for vlm_nav (else task.goal in vlm_nav_config.yaml)
    --kill) tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed $SESSION"; exit 0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
  shift
done

# The bridge connects to the sim node by its robot_nickname. ~/.raisin overrides the package default.
if [[ -z "$PEER" ]]; then
  PEER=$(python3 - <<PY
import re, pathlib
def nick(p):
    try:
        t = pathlib.Path(p).read_text()
    except OSError:
        return None
    m = re.search(r"^robot_nickname:\s*(\S+)\s*$", t, re.M) or re.search(r"^robot_nickname:\s*\n\s*value:\s*(\S+)", t, re.M)
    return m.group(1).strip('"\'') if m else None
print(nick(pathlib.Path.home()/".raisin/raisin_raibo2/params.yaml") or nick("$RAISIN_WS/install/config/raisin_raibo2/config/params.yaml") or "raibo")
PY
)
fi

for f in "$RAISIN_WS/cmake-build-release/src/raisin_raibo2/raisin_raibo2_node" "$RAISIN_WS/ld_prefix_path.sh" \
         "$BRIDGE_WS/install/setup.bash" "$REASONNAV_WS/install/setup.bash" "$ROS_SETUP"; do
  [[ -e "$f" ]] || { echo "missing: $f"; exit 1; }
done
if ! grep -q "raisim_config: /raisim_config/hospital.xml" "$RAISIN_WS/install/config/raisin_raibo2/config/params.yaml"; then
  echo "warning: install/config/raisin_raibo2/config/params.yaml does not select hospital.xml"
fi
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session '$SESSION' already exists (attach: tmux attach -t $SESSION, stop: $0 --kill)"; exit 1
fi

# ReasonNav runs natively here (no docker): warn about Python modules its nodes import.
missing=$(bash -lc "source $ROS_SETUP && source $REASONNAV_WS/install/setup.bash && for m in openai dotenv torch transformers cv_bridge vision_msgs nav2_simple_commander; do python3 -c \"import \$m\" 2>/dev/null || echo -n \"\$m \"; done")
[[ -z "$missing" ]] || echo "warning: python modules missing on host (pip install ...): $missing"

# Colour camera resolution of the simulated OAK mast (the sim reads the install copy): 4K for our pipeline; the ReasonNav stack gets
# 1280x960 (the class of image it was built for) because 33 MB frames cannot be delivered to its single-camera detector fast enough.
XML="$RAISIN_WS/install/resource/raisin_raibo2/resource/sensors/oakd_pro_w_sim.xml"
if [[ $WITH_RN -eq 1 && $RN_DET != inject ]]; then CW=${RN_CAM_W:-1280}; CH=$((CW * 3 / 4)); else CW=${CAM_W:-3840}; CH=$((CW * 3 / 4)); fi
python3 - "$XML" "$CW" "$CH" <<'PYX'
import re, sys
p, w, h = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p).read()
i = t.index('name="color"')
j = t.index('<image', i)
k = t.index('/>', j) + 2
t = t[:j] + '<image width="%s" height="%s"/>' % (w, h) + t[k:]
open(p, 'w').write(t)
PYX
echo "colour camera ${CW}x${CH}"

mkdir -p "$LOG_DIR"
sed "s/@PEER_ID@/$PEER/" "$HERE/bridge_params.yaml.in" > "$LOG_DIR/bridge_params.yaml"
echo "peer_id=$PEER  logs=$LOG_DIR"

# Environment snippets sourced inside each tmux window. ROS_SETUP first so raisin's LD path wins later.
RAISIN_ENV="cd $RAISIN_WS && source $RAISIN_WS/ld_prefix_path.sh >/dev/null"
export ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-45}   # ReasonNav's docker-compose default; keep host and container on one graph
ROS_ENV="${ROOM_FINDER_VLM:+export ROOM_FINDER_VLM=$ROOM_FINDER_VLM && }source $ROS_SETUP && source $BRIDGE_WS/install/setup.bash && source $REASONNAV_WS/install/setup.bash && source $RAISIN_WS/ld_prefix_path.sh >/dev/null && export RAISIN_WS=$RAISIN_WS ROS_DOMAIN_ID=$ROS_DOMAIN_ID"

win() {  # win <name> <command>  -- runs the command, keeps the window open afterwards
  tmux new-window -t "$SESSION" -n "$1" "bash -lc '$2 2>&1 | tee $LOG_DIR/$1.log; echo; echo \"[$1 exited: \$?] press enter to close\"; read'"
}

tmux new-session -d -s "$SESSION" -n raisin \
  "bash -lc '$RAISIN_ENV && stdbuf -oL ./cmake-build-release/src/raisin_raibo2/raisin_raibo2_node 2>&1 | tee $LOG_DIR/raisin.log; echo \"[raisin exited] press enter\"; read'"
sleep 3
if [[ $WITH_GUI -eq 1 ]]; then
  win gui "$RAISIN_ENV && ./cmake-build-release/src/raisin_gui/raisin_gui/raisin_gui"
fi
# raisin_bridge retries until the sim node's raisin_network server is up, so no explicit wait is needed.
win bridge "$ROS_ENV && ros2 run raisin_bridge raisin_bridge_node --ros-args --params-file $LOG_DIR/bridge_params.yaml"
win glue "$ROS_ENV && sleep 5 && python3 $HERE/raisin_nav_glue.py"
# Room finder (three-camera perception + navigator). PYTHONPATH-free: the nodes live in ReasonNav's mm_dev and are run
# from source. OPENAI_API_KEY from ~/.bashrc was stale (401), so the key from mm_dev/config/.env is used unless
# REASONNAV_USE_ENV_KEY=1.
MMDEV=$REASONNAV_WS/src/ReasonNav/src/mm_dev
KEY_ENV="${REASONNAV_USE_ENV_KEY:+:}unset OPENAI_API_KEY"
{ [[ $WITH_RN -eq 0 ]] || [[ $RN_DET == ours ]] || [[ $RN_DET == inject ]]; } && win gdino "/home/user/yolo_ws/.venv_autolabel/bin/python $MMDEV/mm_dev/room_finder/gdino_server.py"
{ [[ $WITH_RN -eq 0 ]] || [[ $RN_DET == inject ]]; } && win perception "$ROS_ENV && $KEY_ENV; sleep 20 && python3 $MMDEV/nodes/room_perception.py --ros-args -p out_dir:=$LOG_DIR/perception ${RECORD_DIR:+-p record_dir:=$RECORD_DIR}"
if [[ $WITH_FINDER -eq 1 ]]; then
  win finder "$ROS_ENV && $KEY_ENV; sleep $([[ $WITH_BRINGUP -eq 1 ]] && echo 70 || echo 30) && python3 $MMDEV/nodes/room_finder.py --ros-args -p target:=${GOAL:-3018} -p out_dir:=$LOG_DIR/finder -p max_time:=$(printf %.1f ${FINDER_MAX_TIME:-1500}) -p policy:=${POLICY:-rule} -p belief_signs:=${BELIEF_SIGNS:-none} -p belief_commit:=${BELIEF_COMMIT:-false} -p belief_range:=$(printf %.1f ${BELIEF_RANGE:-0}) -p belief_numbers:=${BELIEF_NUMBERS:-false} -p belief_verify_base:=$(printf %.1f ${BELIEF_VERIFY_BASE:-25}) -p belief_verify_max:=$(printf %.1f ${BELIEF_VERIFY_MAX:-0}) -p belief_alpha:=$(printf %.2f ${BELIEF_ALPHA:-0.85})"
fi

if [[ $WITH_RN -eq 1 ]]; then
  RN_PY="export PYTHONPATH=$MMDEV:\${PYTHONPATH:-}"   # source tree first: mm_dev.common is identical to the install, but be explicit
  win rn_adapter "$ROS_ENV && $RN_PY && sleep 15 && python3 $HERE/rn_adapter.py --ros-args -p target:=${GOAL:-3018} -p out_dir:=$LOG_DIR -p max_time:=$(printf %.1f ${FINDER_MAX_TIME:-1500})"
  if [[ $RN_DET == inject ]]; then
    :   # no detector: our perception node provides detections and readings
  elif [[ $RN_DET == ours ]]; then
    win detector "$ROS_ENV && $RN_PY && $KEY_ENV; sleep 20 && python3 $HERE/rn_detector_swap.py"
  else
    win detector "$ROS_ENV && $RN_PY && sleep 20 && python3 $MMDEV/nodes/detector.py --ros-args -p use_sim_time:=false -p depth_units:=1"
  fi
  if [[ $RN_DET == inject ]]; then
    win vlm_nav "$ROS_ENV && $RN_PY && $KEY_ENV; sleep 75 && RN_CROPS_DIR=$LOG_DIR/perception/crops REASONNAV_GOAL=${GOAL:-3018} python3 $HERE/rn_vlmnav_ours.py --ros-args -p use_sim_time:=false"
  else
    win vlm_nav "$ROS_ENV && $RN_PY && $KEY_ENV; sleep 75 && REASONNAV_GOAL=${GOAL:-3018} python3 $MMDEV/nodes/vlm_nav.py --ros-args -p use_sim_time:=false"
  fi
fi

if [[ $WITH_RECORD -eq 1 ]]; then
  win recorder "$ROS_ENV && python3 $MMDEV/nodes/room_recorder.py --ros-args -p out:=$LOG_DIR/search.mp4 -p target:=${GOAL:-3018} -p gt_json:=$HERE/gt/hospital_rooms.json"
fi

if [[ $WITH_LEGACY -eq 1 ]]; then
  DETECTOR_CMD="ros2 run mm_dev detector.py --ros-args -p use_sim_time:=false -p depth_units:=1"
  VLM_CMD="$KEY_ENV; ${GOAL:+REASONNAV_GOAL=$GOAL }ros2 run mm_dev vlm_nav.py --ros-args -p use_sim_time:=false"
  win detector "sleep 8 && $ROS_ENV && $DETECTOR_CMD"
  [[ $WITH_VLM -eq 1 ]] && win vlm_nav "sleep 75 && $ROS_ENV && $VLM_CMD"
fi

if [[ $WITH_RVIZ -eq 1 ]]; then
  win rviz "$ROS_ENV && rviz2 -d $HERE/reasonnav_sim.rviz"
fi
if [[ $WITH_BRINGUP -eq 1 ]]; then
  win bringup "$ROS_ENV && sleep 12 && $HERE/bringup.sh ${BRINGUP_CONTROLLER:-blind_locomotion}"
fi

cat <<MSG

started tmux session '$SESSION' (windows: raisin gui bridge glue gdino perception finder rviz bringup; --no-* to skip)
  attach : tmux attach -t $SESSION      (Ctrl-b n / p to switch windows, Ctrl-b d to detach)
  stop   : $0 --kill
  logs   : $LOG_DIR
Robot bring-up: either in the GUI (Connect '$PEER', turn on, stand up, start mapping) or from ROS with
  $HERE/bringup.sh [controller]      (turn_on -> stand-up chain -> set_listen vel_cmd/autonomy -> start_mapping)
The finder searches for room --goal <number> (default 3018) using door plates and navigational signs.
MSG
if [[ -z "${TMUX:-}" && -t 1 ]]; then tmux attach -t "$SESSION"; fi
