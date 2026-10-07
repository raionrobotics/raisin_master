#!/usr/bin/env bash
# For each colour width: start the stack (no finder / gui / rviz), wait, measure, stop.
R=/home/user/raisin_ws; HERE=$R/scripts/reasonnav_sim
source /opt/ros/humble/setup.bash >/dev/null 2>&1; source /home/user/tips_ws/install/setup.bash >/dev/null 2>&1; export ROS_DOMAIN_ID=45
for W in "$@"; do
  $HERE/run_reasonnav_sim.sh --kill >/dev/null 2>&1
  for i in $(seq 1 30); do pgrep -f '[r]aisin_raibo2_node|[r]aisin_bridge_node' >/dev/null || break; pkill -f '[r]aisin_raibo2_node'; pkill -f '[r]aisin_bridge_node'; sleep 2; done; sleep 6
  (cd $R && CAM_W=$W FINDER_MAX_TIME=900 $HERE/run_reasonnav_sim.sh --goal 3036 --no-gui --no-rviz --no-finder </dev/null >/dev/null 2>&1)
  sleep 150
  echo -n "$W: "; python3 $HERE/tools/rate_probe.py 40
done
$HERE/run_reasonnav_sim.sh --kill >/dev/null 2>&1
echo "sweep done"
