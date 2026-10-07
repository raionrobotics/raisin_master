#!/usr/bin/env python3
"""Save the room-finder map as an image: mapdump.py out.png  (free=white, unknown=grey, obstacle=black, robot=red,
plates read=green, doors=blue, signs=orange, GT plates (if gt file exists)=cyan circles)"""
import json, math, os, sys, time
import cv2, numpy as np, rclpy
from nav_msgs.msg import OccupancyGrid
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile
from std_msgs.msg import String
from tf2_ros import Buffer, TransformListener

out = sys.argv[1]
rclpy.init(); n = Node("mapdump"); st = {}
n.create_subscription(OccupancyGrid, "/global_costmap/costmap", lambda m: st.setdefault("map", m), QoSProfile(depth=1, durability=DurabilityPolicy.TRANSIENT_LOCAL))
n.create_subscription(String, "/room_finder/registry", lambda m: st.__setitem__("reg", json.loads(m.data)), 1)
buf = Buffer(); TransformListener(buf, n)
t0 = time.time()
while ("map" not in st or "reg" not in st) and time.time() - t0 < 10:
    rclpy.spin_once(n, timeout_sec=0.2)
m = st["map"]; res = m.info.resolution; W, H = m.info.width, m.info.height
d = np.array(m.data, np.int8).reshape(H, W)
img = np.full((H, W, 3), 160, np.uint8); img[d == 0] = 255; img[d >= 50] = 0
S = 6
img = cv2.resize(img, (W * S, H * S), interpolation=cv2.INTER_NEAREST)
def px(x, y):
    return int((x - m.info.origin.position.x) / res * S), int((y - m.info.origin.position.y) / res * S)
gtp = os.path.expanduser("~/raisin_ws/scripts/reasonnav_sim/gt/hospital_rooms.json")
if os.path.exists(gtp):
    for num, r in json.load(open(gtp))["rooms"].items():
        cv2.circle(img, px(*r["xy"]), 7, (255, 255, 0), 2); cv2.putText(img, num, px(r["xy"][0] + .3, r["xy"][1]), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 150, 0), 1)
reg = st.get("reg", {})
for dr in reg.get("doors", []): cv2.circle(img, px(dr["x"], dr["y"]), 5, (255, 0, 0), -1)
for lb in reg.get("labels", []):
    cv2.circle(img, px(lb["x"], lb["y"]), 8, (0, 200, 0), -1)
    cv2.putText(img, str(lb["number"]), px(lb["x"] + .3, lb["y"] - .3), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 120, 0), 2)
for s in reg.get("signs", []): cv2.rectangle(img, (px(s["x"], s["y"])[0] - 6, px(s["x"], s["y"])[1] - 6), (px(s["x"], s["y"])[0] + 6, px(s["x"], s["y"])[1] + 6), (0, 140, 255), -1)
try:
    t = buf.lookup_transform("map", "base_link", rclpy.time.Time()).transform.translation
    cv2.circle(img, px(t.x, t.y), 9, (0, 0, 255), -1)
except Exception: pass
img = cv2.flip(img, 0)   # +y up
cv2.imwrite(out, img); print("saved", out, img.shape)
