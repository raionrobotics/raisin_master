#!/bin/bash
# A1 r2 (C1) repro: world jinri_1f_clutter_sp_rs_c1, corridor-strip n + aisle start, variants ours/ignore/excl.
# a1c2.sh <round> [cfgs] [targets]   e.g. a1c2.sh 1 ours T110   (one ~5 min check run)
RAISIN_WS=${RAISIN_WS:-$(cd "$(dirname "$0")/../../.." && pwd)}
cd "$RAISIN_WS"
RND=${1:-1}; CFGS=${2:-"ours ignore excl"}; ORDER=${3:-"T110 T111 T127 T129 T113"}
LOG=log/reasonnav_sim/trials/a1c2_batch.log; mkdir -p log/reasonnav_sim/trials
R='RF_PARAMS=room_finder.belief_sign_steer=true,room_finder.sign_seek=100,room_finder.sign_lock=true'
M=$RAISIN_WS/scripts/reasonnav_sim/third_party/mm_dev_r69x; W=",room_finder.sign_neg_strip_w=3.0,room_finder.sign_route_aisle=true"
BASE="CAM_W=1280 RIG=$RAISIN_WS/scripts/room_finder_net/ai_pc/rig_sim1280.yaml AI_MAIN=ai_main_r7f.py GATEWAY=robot_gateway_r7f.py ROOM_FINDER_VLM=gpt-5.4-mini ROOM_FINDER_BELIEF_VLM=gpt-5-mini SIM_NOISE=1 SIM_CAM_HZ=5 SIM_YOLO_MS=42 SIM_GDINO_MS=600 SIM_OCR_MS=350 GW_EXTRA=\"--transient-s 8 --map-res 0.05 --inflate 0.55\""
declare -A CF=([ours]="MMDEV=$M $R$W" [ignore]="MMDEV=$M $R$W SIGN_NEG_PENALTY=0" [excl]="MMDEV=$M $R$W,room_finder.sign_neg_exclude=true")
run() { # room cfg
  local tag=a1c2_$2_r${RND} seed=$(( $(echo $1 | tr -dc 0-9) * 13 + RND * 1000 + 7 ))
  grep -q "\"target\": \"$1\"" log/reasonnav_sim/trials/$tag.jsonl 2>/dev/null && return
  echo "$(date '+%m-%d %T') start $tag $1" >> $LOG
  python3 scripts/reasonnav_sim/run_trials.py $1 --net --world jinri_1f_clutter_sp_rs_c1 --max-time 900 --tag $tag --record --env "$BASE SIM_NOISE_SEED=$seed ${CF[$2]}" >> log/reasonnav_sim/trials/$tag.out 2>&1
  echo "$(date '+%m-%d %T') done $tag $1 $(tail -1 log/reasonnav_sim/trials/$tag.jsonl | python3 -c 'import json,sys;r=json.loads(sys.stdin.read());print(r.get("success"),r.get("elapsed_s"),r.get("path_len_m"))')" | tee -a $LOG
}
for t in $ORDER; do for c in $CFGS; do run $t $c; done; done
