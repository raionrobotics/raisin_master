#!/usr/bin/env python3
"""Watch the room-finder flow on the robot PC without sending anything: the gateway's status (pose, current goal, goals
forwarded to the planner, watchdog) and the planner's velocity command.

    flow_watch.py --vel-node <raisin id> [--vel-topic vel_cmd/navigation] [--duration 120] [--iface lo]"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), os.path.join(HERE, "..", "raisin_py", "build")]
import raisin_boot  # noqa: E402
raisin_boot.preload()
import raisin_py  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--vel-node", default="", help="raisin id of the node publishing the velocity command (empty = gateway status only)")
ap.add_argument("--vel-topic", default="vel_cmd/navigation")
ap.add_argument("--gateway-id", default="room_finder_gw")
ap.add_argument("--iface", nargs="*", default=["lo"])
ap.add_argument("--id", default="room_finder_flow_watch")
ap.add_argument("--duration", type=float, default=120.0)
a = ap.parse_args()

net = raisin_py.Net(a.id, a.iface)
gw = None
for _ in range(30):
    gw = net.connect(a.gateway_id)
    if gw is not None:
        break
    print("waiting for gateway", a.gateway_id, flush=True)
    time.sleep(1.0)
if gw is None:
    raise SystemExit("gateway not reachable")
st = {}
net.subscribe_string(gw, "room_finder/status", lambda s: st.update(json.loads(s)))
vel = {"n": 0, "nonzero": 0, "last": None}
if a.vel_node:
    vc = net.connect(a.vel_node)
    if vc is None:
        print("velocity node %s not reachable: velocity not watched" % a.vel_node, flush=True)
    else:
        def on_vel(vx, vy, wz):
            vel["n"] += 1
            vel["last"] = (round(vx, 3), round(vy, 3), round(wz, 3))
            if abs(vx) + abs(vy) + abs(wz) > 1e-3:
                vel["nonzero"] += 1
        net.subscribe_velocity(vc, a.vel_topic, on_vel)
t0 = time.time()
try:
    while time.time() - t0 < a.duration:
        time.sleep(2.0)
        p, g = st.get("pose"), st.get("goal")
        print("t %5.0f  pose %s  goal %s  goals_sent %s  has_goal %s  watchdog %s  scans %s  | %s %d msgs %d nonzero last %s"
              % (time.time() - t0, None if p is None else [round(v, 2) for v in p[:2]],
                 None if g is None else [round(v, 2) for v in g[:2]], st.get("goals_sent"), st.get("has_goal"),
                 st.get("watchdog_fired"), st.get("scans"), a.vel_topic, vel["n"], vel["nonzero"], vel["last"]), flush=True)
finally:
    print("SUMMARY: goals_sent %s, %s %d msgs (%d nonzero)" % (st.get("goals_sent"), a.vel_topic, vel["n"], vel["nonzero"]), flush=True)
    net.close()
    os._exit(0)
