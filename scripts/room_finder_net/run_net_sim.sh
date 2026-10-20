#!/usr/bin/env bash
# Simulation check of the two-PC setup WITHOUT ROS 2: sim (robot side) + robot_gateway.py  <--raisin_network-->  ai_main.py (AI side).
# Everything runs on this machine over the loopback interface; no ROS environment is sourced.
#   raisin   : raisin_raibo2_node (sim, hospital)
#   bringup  : bringup_sim.py   (turn_on, stand up, autonomy, start_mapping via raisin services)
#   gateway  : robot_gateway.py (robot PC role)
#   gdino    : Grounding DINO server (AI PC role)
#   ai       : ai_main.py       (AI PC role: perception + finder, VLM)
# Usage: run_net_sim.sh --goal <room> [--no-gui] [--kill]
set -euo pipefail
RAISIN_WS=${RAISIN_WS:-/home/user/raisin_ws}
MMDEV=${MMDEV:-/home/user/tips_ws/src/ReasonNav/src/mm_dev}
SESSION=${SESSION:-room_finder_net}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$RAISIN_WS/log/reasonnav_sim/$(date +%Y%m%d_%H%M%S)"
GOAL=3018; WITH_GUI=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --goal) GOAL="$2"; shift ;;
    --gui) WITH_GUI=1 ;;
    --no-gui) WITH_GUI=0 ;;
    --kill) tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed $SESSION"; exit 0 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
  shift
done
PEER=$(python3 - <<PY
import re, pathlib
def nick(p):
    try: t = pathlib.Path(p).read_text()
    except OSError: return None
    m = re.search(r"^robot_nickname:\s*(\S+)\s*$", t, re.M) or re.search(r"^robot_nickname:\s*\n\s*value:\s*(\S+)", t, re.M)
    return m.group(1).strip('"\'') if m else None
import os
print(os.environ.get("PEER_ID") or nick(pathlib.Path.home()/".raisin/raibo2_properties/params.yaml") or nick(pathlib.Path.home()/".raisin/raisin_raibo2/params.yaml") or nick("$RAISIN_WS/install/config/raisin_raibo2/config/params.yaml") or "raibo")
PY
)
tmux has-session -t "$SESSION" 2>/dev/null && { echo "session $SESSION exists (stop: $0 --kill)"; exit 1; }
mkdir -p "$LOG_DIR"
# 4K colour camera as in the ROS-based trials
XML="$RAISIN_WS/install/resource/raisin_raibo2/resource/sensors/oakd_pro_w_sim.xml"
python3 - "$XML" "${CAM_W:-3840}" "$(( ${CAM_W:-3840} * 3 / 4 ))" <<'PYX'
import sys
p, w, h = sys.argv[1:4]
t = open(p).read(); i = t.index('name="color"'); j = t.index('<image', i); k = t.index('/>', j) + 2
open(p, 'w').write(t[:j] + '<image width="%s" height="%s"/>' % (w, h) + t[k:])
PYX
PYP="export PYTHONPATH=$HERE/raisin_py/build"
RAISIN_ENV="cd $RAISIN_WS && source $RAISIN_WS/ld_prefix_path.sh >/dev/null && $PYP"
win() { tmux new-window -t "$SESSION" -n "$1" "bash -lc '$2 2>&1 | tee $LOG_DIR/$1.log; echo \"[$1 exited]\"; read'"; }
tmux new-session -d -s "$SESSION" -n raisin "bash -lc '$RAISIN_ENV && stdbuf -oL ./cmake-build-release/src/raisin_raibo2/raisin_raibo2_node 2>&1 | tee $LOG_DIR/raisin.log; read'"
sleep 3
[[ $WITH_GUI -eq 1 ]] && win gui "$RAISIN_ENV && ./cmake-build-release/src/raisin_gui/raisin_gui/raisin_gui"
win bringup "$RAISIN_ENV && python3 $HERE/ai_pc/bringup_sim.py --robot-id $PEER --log $LOG_DIR/raisin.log"
win gateway "$RAISIN_ENV && sleep 8 && python3 $HERE/robot_pc/robot_gateway.py --robot-id $PEER"
win gdino "/home/user/yolo_ws/.venv_autolabel/bin/python $MMDEV/mm_dev/room_finder/gdino_server.py"
win ai "$RAISIN_ENV && sleep ${AI_DELAY:-75} && POLICY=${POLICY:-belief} BELIEF_SIGNS=${BELIEF_SIGNS:-vlm} BELIEF_COMMIT=${BELIEF_COMMIT:-true} BELIEF_VERIFY_BASE=${BELIEF_VERIFY_BASE:-0} BELIEF_VERIFY_MAX=${BELIEF_VERIFY_MAX:-15} BELIEF_ALPHA=${BELIEF_ALPHA:-0.92} BELIEF_RANGE=${BELIEF_RANGE:-25} ROOM_FINDER_BELIEF_VLM=${ROOM_FINDER_BELIEF_VLM:-gpt-5.4} python3 $HERE/ai_pc/ai_main.py --target $GOAL --robot-id $PEER --max-time ${FINDER_MAX_TIME:-900} --out-dir $LOG_DIR --exit-when-done ${AI_EXTRA:-}"
echo "started tmux session '$SESSION' (peer $PEER, goal $GOAL); logs $LOG_DIR"
