#!/usr/bin/env bash
# Belief-grid policy with picture input, signs off vs on, interleaved per room so partial results stay comparable.
#   img : map picture + confidence-map picture                       (no signs)
#   vlm : the same + cropped sign photos with where / which way they were taken  (no compass parsing, no grid injection)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOMS=${ROOMS:-"3012 3013 3031 3010 3022 3005"}
MODEL=${BELIEF_MODEL:-gpt-5.4}
for r in $ROOMS; do
  for c in img vlm; do
    echo "=== $(date +%T) room $r condition $c"
    python3 "$HERE/run_trials.py" $r --max-time 900 --tag "pm2_$c" --record --env "POLICY=belief BELIEF_SIGNS=$c ROOM_FINDER_BELIEF_VLM=$MODEL"
  done
done
echo "=== $(date +%T) compare finished"
