#!/usr/bin/env python3
"""Video recorder for the room finder: one mp4 per search.

Layout (1600x1000):
  top      3-camera detection board (/room_finder/debug_image: door / sign / plate boxes with ids)
  bottom-l map: lidar occupancy grid, landmarks (plates, doors, signs + cue arrows, frontiers), path, goal, robot trail
  bottom-r reasoning: current goal, hint, top candidates, last VLM plate reads and sign parses, finder log

Starts writing on the first /room_finder/status message and stops (finalising the file) when the finder reports DONE,
or on SIGTERM/SIGHUP/SIGINT.
"""
import collections
import json
import math
import os
import signal
import sys
import time

import cv2
import numpy as np
import rclpy
from nav_msgs.msg import OccupancyGrid
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Image
from std_msgs.msg import String
from visualization_msgs.msg import Marker, MarkerArray

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from mm_dev.room_finder.viz import draw_reason_panel  # noqa: E402

W, H = 1600, 1000
DET_H = 400
MAP_W, MAP_H = 1000, 600
FONT = cv2.FONT_HERSHEY_SIMPLEX


class Recorder(Node):
    def __init__(self):
        super().__init__("room_recorder")
        d = self.declare_parameter
        d("out", "/tmp/room_search.mp4"); d("target", 0); d("fps", 5.0)
        d("xmin", -50.0); d("xmax", 26.0); d("ymin", -10.0); d("ymax", 40.0); d("gt_json", ""); d("tail_s", 4.0)
        g = lambda k: self.get_parameter(k).value  # noqa: E731
        self.out, self.target, self.fps, self.tail_s = g("out"), str(g("target")), float(g("fps")), float(g("tail_s"))
        self.view = (g("xmin"), g("xmax"), g("ymin"), g("ymax"))
        self.gt = None
        if g("gt_json") and self.target not in ("", "0"):
            try:
                G = json.load(open(g("gt_json"))); sp = G["spawn_xy"]; v = G["rooms"][self.target]["xy"]
                self.gt = (v[0] - sp[0], v[1] - sp[1])
            except Exception:  # noqa: BLE001
                pass
        self.writer = None
        self.det = None
        self.grid = None            # (rgb image already warped to the map panel, stamp)
        self.status = None
        self.landmarks, self.path, self.goal = [], [], None
        self.trail = []
        self.reads = collections.deque(maxlen=4)
        self.signs = collections.deque(maxlen=2)
        self.crop_dir = os.path.join(os.path.dirname(os.path.abspath(self.out)), "perception", "crops")
        self._crops = {}
        self.done_at = None
        self.frames = 0
        be = QoSProfile(depth=2, reliability=ReliabilityPolicy.BEST_EFFORT)
        rel = QoSProfile(depth=20, reliability=ReliabilityPolicy.RELIABLE)
        self.create_subscription(Image, "/room_finder/debug_image", self._on_det, be)
        self.create_subscription(String, "/room_finder/status", self._on_status, rel)
        self.create_subscription(String, "/room_finder/events", self._on_event, rel)
        self.create_subscription(MarkerArray, "/room_finder/landmarks", self._on_landmarks, rel)
        self.create_subscription(MarkerArray, "/room_finder/markers", self._on_markers, rel)
        self.create_subscription(OccupancyGrid, "/global_costmap/costmap", self._on_grid,
                                 QoSProfile(depth=1, reliability=ReliabilityPolicy.RELIABLE,
                                            durability=DurabilityPolicy.TRANSIENT_LOCAL))
        self.create_timer(1.0 / self.fps, self._frame)
        self.get_logger().info("room_recorder up: %s (target %s)" % (self.out, self.target))

    # ------------------------------------------------------------------ inputs
    def _on_det(self, m):
        if m.encoding == "bgr8":
            self.det = np.frombuffer(bytes(m.data), np.uint8).reshape(m.height, m.width, 3).copy()

    def _on_status(self, m):
        try:
            st = json.loads(m.data)
        except ValueError:
            return
        if self.status is None:
            self.status = {}
        self.status.update(st)          # the final DONE message carries only the result: keep pose / hint / log from before
        if "elapsed_s" in st:
            self.status["elapsed"] = st["elapsed_s"]
        if st.get("state") == "DONE" and self.done_at is None:
            self.done_at = time.time()
        p = st.get("pose") if st.get("state") != "DONE" else None
        if p and (not self.trail or math.hypot(p[0] - self.trail[-1][0], p[1] - self.trail[-1][1]) > 0.15):
            self.trail.append((p[0], p[1]))

    def _on_event(self, m):
        try:
            e = json.loads(m.data)
        except ValueError:
            return
        if e.get("kind") == "plate_read":
            self.reads.append(e)
        elif e.get("kind") == "sign_read":
            self.signs.append(e)

    def _on_landmarks(self, m):
        self.landmarks = [k for k in m.markers if k.action == Marker.ADD]

    def _on_markers(self, m):
        for k in m.markers:
            if k.ns == "path":
                self.path = [(p.x, p.y) for p in k.points]
            elif k.ns == "goal":
                self.goal = (k.pose.position.x, k.pose.position.y)

    def _on_grid(self, m):
        a = np.array(m.data, np.int8).reshape(m.info.height, m.info.width)
        img = np.full((m.info.height, m.info.width, 3), 70, np.uint8)       # unknown
        img[a == 0] = (238, 238, 238)                                        # free
        img[a >= 50] = (25, 25, 25)                                          # occupied
        img[(a > 0) & (a < 50)] = (200, 200, 200)
        x0, x1, y0, y1 = self.view
        s = self.scale()
        r = m.info.resolution
        M = np.array([[r * s, 0, (m.info.origin.position.x - x0) * s],
                      [0, -r * s, (y1 - m.info.origin.position.y) * s]], np.float32)
        self.grid = cv2.warpAffine(img, M, (self.map_px()[0], self.map_px()[1]), flags=cv2.INTER_NEAREST,
                                   borderValue=(70, 70, 70))

    # ------------------------------------------------------------------ drawing
    def scale(self):
        x0, x1, y0, y1 = self.view
        return min(MAP_W / (x1 - x0), MAP_H / (y1 - y0))

    def map_px(self):
        x0, x1, y0, y1 = self.view
        s = self.scale()
        return int((x1 - x0) * s), int((y1 - y0) * s)

    def px(self, x, y):
        x0, x1, y0, y1 = self.view
        s = self.scale()
        return int((x - x0) * s), int((y1 - y) * s)

    def draw_map(self):
        w, h = self.map_px()
        img = self.grid.copy() if self.grid is not None else np.full((h, w, 3), 70, np.uint8)
        s = self.scale()
        if self.gt:
            c = self.px(*self.gt)
            cv2.drawMarker(img, c, (0, 215, 255), cv2.MARKER_STAR, 22, 2)
            cv2.putText(img, "GT %s" % self.target, (c[0] + 10, c[1] - 8), FONT, 0.45, (0, 140, 200), 1, cv2.LINE_AA)
        for k in self.landmarks:
            col = (int(k.color.b * 255), int(k.color.g * 255), int(k.color.r * 255))
            x, y = k.pose.position.x, k.pose.position.y
            if k.type == Marker.CUBE:
                c = self.px(x, y); r = max(2, int(0.45 * s))
                cv2.rectangle(img, (c[0] - r, c[1] - r), (c[0] + r, c[1] + r), col, -1 if col[1] > 150 else 1)
            elif k.type == Marker.SPHERE:
                cv2.circle(img, self.px(x, y), max(3, int(k.scale.x * s * 0.9)), col, -1)
            elif k.type == Marker.CYLINDER:
                cv2.circle(img, self.px(x, y), max(5, int(0.45 * s)), col, -1)
            elif k.type == Marker.TEXT_VIEW_FACING:
                c = self.px(x, y)
                cv2.putText(img, k.text, (c[0] - 4 * len(k.text), c[1]), FONT, 0.42 if k.scale.z < 0.5 else 0.55, col, 1, cv2.LINE_AA)
            elif k.type == Marker.ARROW and len(k.points) == 2:
                a, b = k.points
                cv2.arrowedLine(img, self.px(a.x, a.y), self.px(b.x, b.y), col, 2 if col[2] > 200 and col[1] < 100 else 1, tipLength=0.15)
        if len(self.path) > 1:
            cv2.polylines(img, [np.array([self.px(*p) for p in self.path], np.int32)], False, (255, 160, 0), 2, cv2.LINE_AA)
        if len(self.trail) > 1:
            cv2.polylines(img, [np.array([self.px(*p) for p in self.trail], np.int32)], False, (200, 0, 200), 1, cv2.LINE_AA)
        if self.goal:
            cv2.circle(img, self.px(*self.goal), max(5, int(0.4 * s)), (0, 90, 255), 2)
        if self.status and self.status.get("pose"):
            x, y = self.status["pose"]; yaw = self.status.get("yaw", 0.0)
            c = self.px(x, y)
            cv2.circle(img, c, max(5, int(0.5 * s)), (0, 0, 220), -1)
            cv2.arrowedLine(img, c, (c[0] + int(26 * math.cos(yaw)), c[1] - int(26 * math.sin(yaw))), (0, 0, 220), 3, tipLength=0.4)
        out = np.full((MAP_H, MAP_W, 3), 40, np.uint8)
        out[:img.shape[0], :img.shape[1]] = img[:MAP_H, :MAP_W]
        return out

    @staticmethod
    def put(img, text, x, y, scale=0.5, col=(230, 230, 230), th=1):
        cv2.putText(img, text, (x, y), FONT, scale, col, th, cv2.LINE_AA)
        return y + int(26 * scale / 0.5 * 0.9)

    def crop(self, name):
        if not name:
            return None
        if name not in self._crops:
            self._crops[name] = cv2.imread(os.path.join(self.crop_dir, name))
        return self._crops[name]

    def draw_reason(self):
        st = self.status or {}
        reads = [dict(e, crop=self.crop(e.get("crop"))) for e in self.reads]
        sign = dict(self.signs[-1], crop=self.crop(self.signs[-1].get("crop"))) if self.signs else None
        return draw_reason_panel({"target": self.target, "item": st.get("item"), "hint": st.get("hint", "-"), "cands": st.get("cands"), "belief": st.get("belief"),
                                  "log": st.get("log", []), "reads": reads, "sign": sign})

    def _frame(self):
        st = self.status
        if st is None:
            return
        if self.writer is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.out)), exist_ok=True)
            self.writer = cv2.VideoWriter(self.out, cv2.VideoWriter_fourcc(*"mp4v"), self.fps, (W, H))
        canvas = np.full((H, W, 3), 20, np.uint8)
        if self.det is not None:
            canvas[:DET_H] = cv2.resize(self.det, (W, DET_H), interpolation=cv2.INTER_AREA)
        canvas[DET_H:, :MAP_W] = self.draw_map()
        canvas[DET_H:, MAP_W:] = self.draw_reason()
        head = "target %s   t=%ds   path %.0f m   %s" % (self.target, st.get("elapsed", 0), st.get("path_len", 0.0), st.get("state", ""))
        cv2.rectangle(canvas, (0, 0), (W, 30), (0, 0, 0), -1)
        cv2.putText(canvas, head, (10, 22), FONT, 0.7, (255, 255, 255), 2, cv2.LINE_AA)
        if self.done_at is not None:
            ok = bool(st.get("found"))
            cv2.putText(canvas, "FOUND %s" % self.target if ok else "GAVE UP %s" % self.target, (W // 2 - 200, DET_H + 60), FONT, 1.6,
                        (60, 220, 60) if ok else (60, 60, 255), 4, cv2.LINE_AA)
        self.writer.write(canvas)
        self.frames += 1
        if self.done_at is not None and time.time() - self.done_at > self.tail_s:
            self.close()
            raise SystemExit(0)

    def close(self):
        if self.writer is not None:
            self.writer.release(); self.writer = None
            self.get_logger().info("saved %s (%d frames)" % (self.out, self.frames))


def main():
    rclpy.init()
    node = Recorder()

    def stop(*_):
        node.close()
        os._exit(0)
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(s, stop)
    try:
        rclpy.spin(node)
    except SystemExit:
        pass
    finally:
        node.close()


if __name__ == "__main__":
    main()
