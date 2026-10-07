#!/usr/bin/env bash
# Three-way comparison, interleaved per room (so partial results stay comparable):
#   img : belief grid, picture input (map + confidence map), no signs
#   vlm : belief grid + sign photos with where / which way they were taken
#   lm  : ReasonNav-style landmark map (vlm_nav with our detection + plate / sign reading)
#   run_signs_study.sh <prefix> "<rooms>" [conds...]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=$1; ROOMS=$2; shift 2
CONDS=${*:-"img vlm lm"}
MODEL=${BELIEF_MODEL:-gpt-5.4}
for r in $ROOMS; do
  for c in $CONDS; do
    case "$c" in
      img) ENVV="POLICY=belief BELIEF_SIGNS=img ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlm) ENVV="POLICY=belief BELIEF_SIGNS=vlm ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      imgc) ENVV="POLICY=belief BELIEF_SIGNS=img BELIEF_COMMIT=true ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlmc) ENVV="POLICY=belief BELIEF_SIGNS=vlm BELIEF_COMMIT=true ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlmr) ENVV="POLICY=belief BELIEF_SIGNS=vlm BELIEF_COMMIT=true BELIEF_RANGE=25 ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlmn) ENVV="POLICY=belief BELIEF_SIGNS=vlm BELIEF_COMMIT=true BELIEF_NUMBERS=true ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlmrn) ENVV="POLICY=belief BELIEF_SIGNS=vlm BELIEF_COMMIT=true BELIEF_RANGE=25 BELIEF_NUMBERS=true ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      img4) ENVV="POLICY=belief BELIEF_SIGNS=img BELIEF_COMMIT=true BELIEF_VERIFY_BASE=0 BELIEF_VERIFY_MAX=15 BELIEF_ALPHA=0.92 BELIEF_RANGE=25 ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlm4) ENVV="POLICY=belief BELIEF_SIGNS=vlm BELIEF_COMMIT=true BELIEF_VERIFY_BASE=0 BELIEF_VERIFY_MAX=15 BELIEF_ALPHA=0.92 BELIEF_RANGE=25 ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      vlmp4) ENVV="POLICY=belief BELIEF_SIGNS=vlmp BELIEF_COMMIT=true BELIEF_VERIFY_BASE=0 BELIEF_VERIFY_MAX=15 BELIEF_ALPHA=0.92 BELIEF_RANGE=25 ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      steer4) ENVV="POLICY=belief BELIEF_SIGNS=steer BELIEF_COMMIT=true BELIEF_VERIFY_BASE=0 BELIEF_VERIFY_MAX=15 BELIEF_ALPHA=0.92 BELIEF_RANGE=25 ROOM_FINDER_BELIEF_VLM=$MODEL"; EXTRA="" ;;
      lm)  ENVV="POLICY=rule"; EXTRA="--rn --rn-det inject" ;;
      *)   ENVV="$c"; EXTRA="" ;;
    esac
    echo "=== $(date +%T) room $r condition $c"
    python3 "$HERE/run_trials.py" $r --max-time 900 --tag "${PREFIX}_$c" --record --env "$ENVV" "--extra=$EXTRA" || { echo "=== ABORT $(date +%T): the finder crashed on start (see FINDER_CRASH above)"; exit 1; }
  done
done
echo "=== $(date +%T) study finished"
