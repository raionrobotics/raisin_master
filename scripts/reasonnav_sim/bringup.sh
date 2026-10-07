#!/usr/bin/env bash
# Bring the simulated raibo up through the bridged raisin services, without the GUI:
#   turn_on -> transition_to_state <controller> (init_motor, joint_test, stand_up, load_controller)
#   -> set_listen vel_cmd/autonomy (let the navigation plugin drive)
# Usage: bringup.sh [controller]   (default: blind_locomotion)
set -o pipefail
CTRL=${1:-blind_locomotion}
RAISIN_WS=${RAISIN_WS:-/home/user/raisin_ws}
BRIDGE_WS=${BRIDGE_WS:-/home/user/raisin_bridge_ws}
source ${ROS_SETUP:-/opt/ros/humble/setup.bash}
source "$BRIDGE_WS/install/setup.bash"
export ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-45}
LOG=$(ls -td "$RAISIN_WS"/log/reasonnav_sim/*/ 2>/dev/null | head -1)raisin.log

call() { timeout 30 ros2 service call "$@" 2>&1 | grep -oE "success=[A-Za-z]+, message='[^']*'" || echo "no response from $1"; }

echo "[bringup] waiting for bridged services"
until timeout 10 ros2 service list 2>/dev/null | grep -q "^/transition_to_state$"; do sleep 2; done

echo "[bringup] turn_on";  call /turn_on std_srvs/srv/Trigger
sleep 8   # plugins load after turn_on
echo "[bringup] transition_to_state -> $CTRL"
before=$(grep -c "waiting for user confirmation" "$LOG" 2>/dev/null); before=${before:-0}
call /transition_to_state raisin_interfaces/srv/String "{data: '$CTRL'}"
# The joint test may raise a diagnostic warning (e.g. IMU noise in sim) that must be confirmed
# within 10 s with the confirmation id (= the running count of such requests).
for i in $(seq 1 60); do
  sleep 1
  now=$(grep -c "waiting for user confirmation" "$LOG" 2>/dev/null); now=${now:-0}
  if [[ "$now" -gt "$before" ]]; then
    echo "[bringup] joint_test warning -> confirming (id $now)"
    call /confirm_state_chain raisin_interfaces/srv/StringAndBool "{data: '$now', flag: true}"
    before=$now
  fi
  if grep -q "load controller: $CTRL" "$LOG" 2>/dev/null; then echo "[bringup] controller loaded"; break; fi
  if grep -q "controller chain canceled" <(tail -n 20 "$LOG" 2>/dev/null); then echo "[bringup] chain canceled, see $LOG"; exit 1; fi
done
echo "[bringup] set_listen vel_cmd/autonomy"; call /set_listen raisin_interfaces/srv/String "{data: 'vel_cmd/autonomy'}"
# lidar_slam stays idle (no /Odometry/base -> navigation never plans) until mapping is started
echo "[bringup] start_mapping (lidar_slam)"; call /start_mapping std_srvs/srv/Trigger
echo "[bringup] base pose:"; timeout 10 ros2 topic echo /Odometry/state_estimator --qos-reliability best_effort --once 2>/dev/null | grep -A3 "position:" | head -4
