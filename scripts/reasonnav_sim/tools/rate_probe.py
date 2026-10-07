#!/usr/bin/env python3
"""Count how fast each camera stream arrives (receive only) and how many frames the perception node processed. Usage: rate_probe.py [seconds]"""
import json, sys, time
import rclpy
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Image
from std_msgs.msg import String
T = float(sys.argv[1]) if len(sys.argv) > 1 else 40
rclpy.init()
n = Node("rate_probe")
be = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
cnt = {}
def mk(t):
    cnt[t] = 0
    n.create_subscription(Image, t, lambda m, t=t: cnt.__setitem__(t, cnt[t] + 1), be)
for c in ("front", "left", "right"):
    mk(f"/oak_{c}/rgb"); mk(f"/oak_{c}/depth")
reg = []
n.create_subscription(String, "/room_finder/registry", lambda m: reg.append((time.time(), json.loads(m.data)["stats"])), 5)
ex = MultiThreadedExecutor(4); ex.add_node(n)
t0 = time.time()
while time.time() - t0 < T:
    ex.spin_once(timeout_sec=0.1)
rgb = sum(v for k, v in cnt.items() if k.endswith("rgb")) / T / 3
dep = sum(v for k, v in cnt.items() if k.endswith("depth")) / T / 3
proc = 0.0
if len(reg) >= 2:
    dt = reg[-1][0] - reg[0][0]
    proc = (reg[-1][1]["frames"] - reg[0][1]["frames"]) / dt / 3
print(json.dumps({"rgb_hz_per_camera": round(rgb, 2), "depth_hz_per_camera": round(dep, 2), "processed_per_camera": round(proc, 2)}))
