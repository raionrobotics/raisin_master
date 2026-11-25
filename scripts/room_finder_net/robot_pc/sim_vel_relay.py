#!/usr/bin/env python3
"""Simulation-only relay: the robot follows raisin navigation's MPPI command again.

In the 2026-10-15 raisin build the navigation process computes its velocity command (relayed by the navigation plugin as
navigation/vis/mppi_cmd) but the robot node's joy interface never receives the process's vel_cmd/autonomy, so the
simulated robot stands still.  This republishes navigation/vis/mppi_cmd as vel_cmd/autonomy from its own network node and
points the joy interface at it with set_listen "vel_cmd/autonomy<&><this id>".  Planning and control stay raisin
navigation's; only the transport is replaced.  Not for the real robot.

    sim_vel_relay.py --robot-id <nickname> [--iface lo]"""
import argparse
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), os.path.join(HERE, "..", "raisin_py", "build")]
import raisin_boot  # noqa: E402

raisin_boot.preload()
import raisin_py  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--robot-id", required=True)
ap.add_argument("--id", default="room_finder_vel_relay")
ap.add_argument("--iface", nargs="*", default=["lo"])
ap.add_argument("--src-topic", default="navigation/vis/mppi_cmd")
ap.add_argument("--timeout", type=float, default=0.3, help="publish zero when navigation is silent this long (s)")
a = ap.parse_args()

net = raisin_py.Net(a.id, a.iface)
robot = None
while robot is None:
    try:
        robot = net.connect(a.robot_id)
    except Exception:  # noqa: BLE001
        time.sleep(1.0)
pub = net.publisher_velocity("vel_cmd/autonomy")
last = {"t": 0.0, "n": 0}
lock = threading.Lock()


def on_cmd(x, y, w):
    with lock:
        last["t"], last["n"] = time.time(), last["n"] + 1
    pub.publish(x, y, w, 0.5)


net.subscribe_velocity(robot, a.src_topic, on_cmd)
print("[vel_relay] %s -> vel_cmd/autonomy (as %s)" % (a.src_topic, a.id), flush=True)
listened, t_log = False, 0.0
while True:
    time.sleep(0.1)
    with lock:
        silent = time.time() - last["t"] > a.timeout
        n = last["n"]
    if silent:
        pub.publish(0.0, 0.0, 0.0, 0.5)      # keep the source alive (and the robot still) while navigation has no plan
    if not listened:
        try:
            ok, msg = net.call_string(robot, "set_listen", "vel_cmd/autonomy<&>%s" % a.id, 5.0)
        except Exception as e:  # noqa: BLE001
            ok, msg = False, repr(e)
        print("[vel_relay] set_listen -> %s %s" % (ok, msg), flush=True)
        listened = bool(ok)
    if time.time() - t_log > 30:
        t_log = time.time()
        print("[vel_relay] relayed %d commands" % n, flush=True)
