#!/usr/bin/env python3
"""ReasonNav's vlm_nav (the modified version, unchanged) fed with OUR detection + recognition instead of its own.

Our perception node (3 OAK cameras at 4K: YOLO door model + Grounding DINO + VLM plate / sign reading, ≥2 concordant reads per plate)
publishes /room_finder/registry. This wrapper loads vlm_nav.py as a module and adds one 1 Hz timer that pushes that registry into
vlm_nav's own data structures the way its own detector / OCR would have:
  doors            -> landmark_db['a door'] (through vlm_nav's detection_callback, class 'a door')
  accepted plates  -> door label: _door_conf + landmark_db.mark_visited(label=...)  (what _ocr_room does after a reading); if the plate is
                      the goal and the robot is within 3.5 m, announce_found()  (same "in passing" rule: plates only count within 8 m)
  signs with cues  -> landmark_db['a directional sign'] + sign_views[idx] {entries [{label, arrow}], photo = our crop of the sign}
vlm_nav's own landmark choice (the VLM with the map image, sign photos and corridor context), planning, queue and navigation are untouched;
its detector and OCR are simply not running.
"""
import importlib.util, glob, json, math, os, sys, time

import cv2
import numpy as np
import rclpy
from geometry_msgs.msg import Pose
from std_msgs.msg import String
from vision_msgs.msg import Detection2D, Detection2DArray, ObjectHypothesisWithPose
from geometry_msgs.msg import PoseWithCovariance

MMDEV = "/home/user/tips_ws/src/ReasonNav/src/mm_dev"
sys.path.insert(0, MMDEV)
sys.path.insert(0, MMDEV + "/nodes")   # vlm_nav imports landmark_handlers etc. from its own directory
spec = importlib.util.spec_from_file_location("vlm_nav", MMDEV + "/nodes/vlm_nav.py")
vn = importlib.util.module_from_spec(spec)
sys.modules["vlm_nav"] = vn
spec.loader.exec_module(vn)
V = vn.VLMNav
CROPS = os.environ.get("RN_CROPS_DIR", "")
ARROW = {"straight": "up", "back": "down", "left": "left", "right": "right"}   # diagonals have no ReasonNav equivalent -> 'none'


def pose_at(x, y, z, yaw):
    p = Pose()
    p.position.x, p.position.y, p.position.z = float(x), float(y), float(z)
    p.orientation.z, p.orientation.w = math.sin(yaw / 2), math.cos(yaw / 2)
    return p


def det(cls, x, y, z, yaw, score=0.9):
    d = Detection2D()
    d.bbox.size_x, d.bbox.size_y = 100.0, 200.0
    d.bbox.center.position.x, d.bbox.center.position.y = 640.0, 480.0
    h = ObjectHypothesisWithPose()
    h.pose = PoseWithCovariance()
    h.pose.pose = pose_at(x, y, z, yaw)
    h.hypothesis.class_id, h.hypothesis.score = cls, float(score)
    d.results.append(h)
    return d


def sign_photo(sid):
    fs = sorted(glob.glob("%s/sign_s%d_*.jpg" % (CROPS, sid))) if CROPS else []
    for f in reversed(fs):
        im = cv2.imread(f)
        if im is not None:
            return im
    return np.full((200, 300, 3), 127, np.uint8)


def inject(self):
    reg = getattr(self, "_ours", None)
    if not reg or self.robot_pose is None:
        return
    rx, ry, _ = vn.pose_msg_to_xyyaw(self.robot_pose)
    stamp = self.get_clock().now().to_msg()
    msg = Detection2DArray()
    msg.header.frame_id, msg.header.stamp = "map", stamp
    for d in reg.get("doors", []):
        if d.get("n", 0) >= 3:
            nrm = d.get("nrm") or [1.0, 0.0]
            msg.detections.append(det("a door", d["x"], d["y"], 1.0, math.atan2(nrm[1], nrm[0])))
    if msg.detections:
        self.detection_callback(msg)
    # plates -> door labels
    for lb in reg.get("labels", []):
        n = lb.get("number")
        if not n or math.hypot(lb["x"] - rx, lb["y"] - ry) > 8.0:
            continue
        door = self._nearest_door((lb["x"], lb["y"]))
        if door is None:
            self.landmark_db.add_det("a door", pose_at(lb["x"], lb["y"], 1.0, 0.0), 0.5)
            door = len(self.landmark_db.landmark_db["a door"]["positions"]) - 1
        cur = self._door_conf.get(door)
        if not cur or cur[0] != n:
            self._door_conf[door] = (n, 0.95, 100.0)
            self.landmark_db.mark_visited("a door", door, label=n)
            self.get_logger().info("[ours] room %s (score %.1f) -> door %d at (%.1f, %.1f)" % (n, lb.get("score", 0), door, lb["x"], lb["y"]))
        if self.landmark_handlers._is_goal(n) and math.hypot(lb["x"] - rx, lb["y"] - ry) <= 3.5:
            self.announce_found(n, (lb["x"], lb["y"]))
    # signs -> landmarks + sign_views
    sm = Detection2DArray()
    sm.header.frame_id, sm.header.stamp = "map", stamp
    usable = [s for s in reg.get("signs", []) if s.get("cues") and not s.get("dead") and s.get("reads", 0) >= 2]
    for s in usable:
        nx = s.get("n") or [1.0, 0.0]
        sm.detections.append(det("a directional sign", s["x"], s["y"], 1.6, math.atan2(nx[1], nx[0])))
    if not sm.detections:
        return
    # register the landmarks only (detection_callback would try to read a camera frame for the crop)
    for s, d in zip(usable, sm.detections):
        obj = d.results[0]
        cls = "a directional sign"
        if cls in self.landmark_db.landmark_db:
            idx = self.landmark_db.update_det(cls, obj.pose.pose, 0.9)
        else:
            self.landmark_db.add_det(cls, obj.pose.pose, 0.9)
            idx = 0
        entries = []
        for c in s["cues"]:
            if c.get("lo") is not None:
                label = "%d-%d" % (c["lo"], c["hi"]) if c["lo"] != c["hi"] else str(c["lo"])
            else:
                label = c["place"]
            entries.append({"label": label, "arrow": ARROW.get(c.get("direction"), "none")})
        nx = s.get("n") or [1.0, 0.0]
        photo = sign_photo(s["id"])
        with self.room_lock:
            prev = self.sign_views.get(idx) or {}
            self.sign_views[idx] = {"img": photo, "crop": photo, "score": 1.0, "area": 1e5,
                                    "robot_xy": (s["x"] + 2.5 * nx[0], s["y"] + 2.5 * nx[1]), "entries": entries, "tries": 99,
                                    "read_area": 1e5, "final": True}
            self.landmark_db.landmark_db[cls]["visited"] = self.landmark_db.landmark_db[cls].get("visited", [])


_orig_init = V.__init__


def _init(self, *a, **k):
    _orig_init(self, *a, **k)
    self._ours = None

    def on_reg(m):
        try:
            self._ours = json.loads(m.data)
        except ValueError:
            pass
    self.create_subscription(String, "/room_finder/registry", on_reg, 5)

    def tick():
        try:
            inject(self)
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("ours inject failed: %r" % e)
    self.create_timer(1.0, tick)
    self.get_logger().info("[ours] injecting our detection + recognition into vlm_nav (crops %s)" % CROPS)


V.__init__ = _init

if __name__ == "__main__":
    vn.main()
