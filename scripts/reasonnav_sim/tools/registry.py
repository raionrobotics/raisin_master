#!/usr/bin/env python3
"""Print the room finder registry once: registry.py [--raw]"""
import json, sys, time
import rclpy
from rclpy.node import Node
from std_msgs.msg import String

rclpy.init(); n = Node("registry_dump"); got = []
n.create_subscription(String, "/room_finder/registry", lambda m: got.append(json.loads(m.data)), 1)
t0 = time.time()
while not got and time.time() - t0 < 10:
    rclpy.spin_once(n, timeout_sec=0.2)
if not got:
    print("no registry message"); sys.exit(1)
j = got[0]
if "--raw" in sys.argv:
    print(json.dumps(j, indent=1)); sys.exit(0)
print("stats", j["stats"], "pending", j["pending"])
print("doors :", len(j["doors"]), [(d["id"], round(d["x"], 1), round(d["y"], 1), d["n"], d["label"]) for d in j["doors"]][:12])
print("labels:", [(l["number"], round(l["x"], 1), round(l["y"], 1), l["reads"]) for l in j["labels"]])
for s in j["signs"]:
    print("sign %d at (%.1f, %.1f) reads=%d q=%.2f" % (s["id"], s["x"], s["y"], s["reads"], s["best_q"]))
    for c in s["cues"]:
        b = c.get("bearing")
        print("   %-40s %-14s %s" % (c["place"], c["direction"], "" if b is None else "bearing %.0f deg" % (b * 57.3)))
