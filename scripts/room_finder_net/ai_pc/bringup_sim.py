#!/usr/bin/env python3
"""Bring the simulated raibo up through raisin services (no ROS 2) -- the same chain as reasonnav_sim/bringup.sh:
turn_on -> transition_to_state <controller> (joint-test warnings are confirmed) -> set_listen vel_cmd/autonomy -> start_mapping.
On a real robot do this from the raisin GUI / remote instead.

  bringup_sim.py --robot-id <nickname> --log <raisin.log of the sim node> [--controller blind_locomotion]
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "raisin_py", "build"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import raisin_boot  # noqa: E402
raisin_boot.preload()
import raisin_py  # noqa: E402


def count(path, text):
    try:
        return sum(text in ln for ln in open(path, errors="ignore"))
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--robot-id", required=True)
    ap.add_argument("--log", required=True, help="stdout log of the sim's raisin node (joint-test confirmations are read from it)")
    ap.add_argument("--controller", default="blind_locomotion")
    ap.add_argument("--iface", nargs="*", default=["lo"])
    ap.add_argument("--id", default="room_finder_bringup")
    a = ap.parse_args()
    net = raisin_py.Net(a.id, a.iface)
    conn = None
    while conn is None:
        conn = net.connect(a.robot_id)
        time.sleep(1.0)
    print("[bringup] connected to", a.robot_id, flush=True)

    def call(name, *args, fn="call_string"):
        ok, msg = getattr(net, fn)(conn, name, *args)
        print("[bringup] %s -> %s %s" % (name, ok, msg), flush=True)
        return ok

    while not net.call_trigger(conn, "turn_on", 3.0)[0]:      # waits until the service exists
        time.sleep(2.0)
    print("[bringup] turn_on ok", flush=True)
    time.sleep(8)
    before = count(a.log, "waiting for user confirmation")
    res = {}
    th = threading.Thread(target=lambda: res.update(r=net.call_string(conn, "transition_to_state", a.controller, 180.0)), daemon=True)
    th.start()
    for _ in range(90):
        time.sleep(1.0)
        now = count(a.log, "waiting for user confirmation")
        if now > before:
            print("[bringup] joint_test warning -> confirm (id %d)" % now, flush=True)
            call("confirm_state_chain", str(now), True, fn="call_string_and_bool")
            before = now
        if count(a.log, "load controller: %s" % a.controller):
            print("[bringup] controller loaded", flush=True)
            break
        if "canceled" in "".join(open(a.log, errors="ignore").readlines()[-20:]) and "controller chain canceled" in open(a.log, errors="ignore").read():
            print("[bringup] chain canceled, see", a.log, flush=True)
            sys.exit(1)
    th.join(timeout=5)
    print("[bringup] transition_to_state ->", res.get("r"), flush=True)
    call("set_listen", "vel_cmd/autonomy")
    call("start_mapping", 30.0, fn="call_trigger")
    net.close()


if __name__ == "__main__":
    main()
