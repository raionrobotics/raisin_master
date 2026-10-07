#!/usr/bin/env bash
# Unattended policy comparison on a fixed room subset (serial, one clean stack per room, video recorded).
#   run_policy_matrix.sh <tag-prefix> <cond> [<cond> ...]       cond in: rule | belief | belief_signs
# All conditions use ROOM_FINDER_VLM (default gpt-5-mini) and the YOLO-door + Grounding DINO + VLM detection.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOMS=${ROOMS:-"3010 3012 3013 3031 3040 3005 3022 3030"}
MAXT=${MAXT:-900}
PREFIX=$1; shift
for cond in "$@"; do
  case "$cond" in
    rule)          ENVV="POLICY=rule"; EXTRA="" ;;
    belief)        ENVV="POLICY=belief BELIEF_SIGNS=none"; EXTRA="" ;;
    belief_signs)  ENVV="POLICY=belief BELIEF_SIGNS=both"; EXTRA="" ;;
    belief_vlm)    ENVV="POLICY=belief BELIEF_SIGNS=vlm"; EXTRA="" ;;   # map picture + sign photos with viewpoint, all handled by the VLM
    rn_ours)       ENVV="POLICY=rule"; EXTRA="--rn --rn-det inject" ;;   # ReasonNav vlm_nav with OUR detection + plate/sign reading
    *) echo "unknown condition $cond"; continue ;;
  esac
  EXTRA=${EXTRA:-}
  echo "=== $(date +%T) condition $cond ($ENVV)"
  python3 "$HERE/run_trials.py" $ROOMS --max-time "$MAXT" --tag "${PREFIX}_${cond}" --record --env "$ENVV" "--extra=${EXTRA:-}"
done
echo "=== $(date +%T) matrix finished"
