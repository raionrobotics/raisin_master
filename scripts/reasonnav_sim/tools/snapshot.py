#!/usr/bin/env python3
"""Save one colour + depth frame from each OAK camera: snapshot.py <out_dir> [cameras...]"""
import sys, time
import numpy as np, cv2, rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Image

out = sys.argv[1]; cams = sys.argv[2:] or ["oak_front", "oak_left", "oak_right"]
rclpy.init(); n = Node("snapshot")
got = {}
qos = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
def dec(m):
    if m.encoding == "32FC1":
        return np.frombuffer(bytes(m.data), np.float32).reshape(m.height, m.width)
    return np.frombuffer(bytes(m.data), np.uint8).reshape(m.height, m.width, 3)
for c in cams:
    for k in ("rgb", "depth"):
        n.create_subscription(Image, f"/{c}/{k}", lambda m, key=(c, k): got.setdefault(key, dec(m)), qos)
t0 = time.time()
while rclpy.ok() and len(got) < 2 * len(cams) and time.time() - t0 < 30:
    rclpy.spin_once(n, timeout_sec=0.2)
for (c, k), a in got.items():
    if k == "rgb":
        cv2.imwrite(f"{out}/{c}_rgb.png", a)
    else:
        v = a[np.isfinite(a) & (a > 0)]
        print(f"{c} depth: shape={a.shape} valid={v.size / a.size:.2f} min={v.min() if v.size else 0:.2f} "
              f"median={np.median(v) if v.size else 0:.2f} max={v.max() if v.size else 0:.2f}")
        np.save(f"{out}/{c}_depth.npy", a)
        d8 = np.clip(np.nan_to_num(a) / 8.0 * 255, 0, 255).astype(np.uint8)
        cv2.imwrite(f"{out}/{c}_depth.png", cv2.applyColorMap(d8, cv2.COLORMAP_TURBO))
print("saved", sorted(f"{c}_{k}" for c, k in got))
