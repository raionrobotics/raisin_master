#!/usr/bin/env python3
"""Send one short goal through the gateway (as the AI PC would) and watch the robot reach it.

    goal_test.py [--dist 1.0] [--timeout 40] [--iface lo] [--gateway-id room_finder_gw]
                 [--vel-node <raisin id> --vel-topic vel_cmd/navigation]   (also print the planner's velocity commands)

Reads the robot pose from the gateway's `room_finder/status`, sends a goal --dist m straight ahead through service
`room_finder/goal` every 2 s (the gateway's watchdog cancels a goal that is not refreshed), prints the distance to the goal,
and calls `room_finder/stop` at the end (reached, timeout or Ctrl-C)."""
import argparse
import json
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), os.path.join(HERE, "..", "raisin_py", "build")]
import raisin_boot  # noqa: E402
raisin_boot.preload()
import raisin_py  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--dist", type=float, default=1.0)
ap.add_argument("--timeout", type=float, default=40.0)
ap.add_argument("--reach", type=float, default=0.35, help="goal counts as reached within this distance (m)")
ap.add_argument("--iface", nargs="*", default=["lo"])
ap.add_argument("--gateway-id", default="room_finder_gw")
ap.add_argument("--id", default="room_finder_goal_test")
ap.add_argument("--vel-node", default="", help="raisin id of the node publishing the velocity command (empty = don't watch)")
ap.add_argument("--vel-topic", default="vel_cmd/navigation")
a = ap.parse_args()

net = raisin_py.Net(a.id, a.iface)
gw = None
for _ in range(30):
    gw = net.connect(a.gateway_id)
    if gw is not None:
        break
    print("waiting for gateway", a.gateway_id)
    time.sleep(1.0)
if gw is None:
    raise SystemExit("gateway not reachable")
st = {}
net.subscribe_string(gw, "room_finder/status", lambda s: st.update(json.loads(s)))
t0 = time.time()
while not st.get("pose") and time.time() - t0 < 10:
    time.sleep(0.2)
if not st.get("pose"):
    raise SystemExit("no robot pose in room_finder/status after 10 s (odometry topic not arriving at the gateway?)")
vel = {"n": 0, "nonzero": 0, "last": None}
if a.vel_node:
    vc = net.connect(a.vel_node)
    if vc is None:
        print("velocity node %s not reachable: velocity not watched" % a.vel_node)
    else:
        def on_vel(vx, vy, wz):
            vel["n"] += 1
            vel["last"] = (round(vx, 3), round(vy, 3), round(wz, 3))
            if abs(vx) + abs(vy) + abs(wz) > 1e-3:
                vel["nonzero"] += 1
        net.subscribe_velocity(vc, a.vel_topic, on_vel)
x0, y0, _, yaw0 = st["pose"]
gx, gy = x0 + a.dist * math.cos(yaw0), y0 + a.dist * math.sin(yaw0)
print("start (%.2f, %.2f) yaw %.2f -> goal (%.2f, %.2f)" % (x0, y0, yaw0, gx, gy))
reached = False
try:
    t0 = t_send = 0.0
    t0 = time.time()
    while time.time() - t0 < a.timeout:
        if time.time() - t_send > 2.0:
            ok, msg = net.call_string(gw, "room_finder/goal", json.dumps({"x": gx, "y": gy, "yaw": yaw0, "use_yaw": False}), 3.0)
            t_send = time.time()
            if not ok:
                print("goal rejected:", msg)
        p = st.get("pose")
        d = math.hypot(gx - p[0], gy - p[1])
        print("t %5.1f  pose (%.2f, %.2f)  to goal %.2f m  has_goal %s  sent %s  watchdog %s  %s: %d msgs, %d nonzero, last %s"
              % (time.time() - t0, p[0], p[1], d, st.get("has_goal"), st.get("goals_sent"), st.get("watchdog_fired"),
                 a.vel_topic, vel["n"], vel["nonzero"], vel["last"]))
        if d < a.reach:
            reached = True
            break
        time.sleep(1.0)
finally:
    print("stop:", net.call_string(gw, "room_finder/stop", "{}", 3.0))
    p = st.get("pose")
    print("RESULT: %s, moved %.2f m, %s: %d msgs (%d nonzero)"
          % ("REACHED" if reached else "NOT reached", math.hypot(p[0] - x0, p[1] - y0), a.vel_topic, vel["n"], vel["nonzero"]))
    net.close()
    os._exit(0)
