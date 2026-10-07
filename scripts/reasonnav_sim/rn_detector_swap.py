#!/usr/bin/env python3
"""Drop-in replacement for ReasonNav's detector.py that uses OUR detection module (the one the rule / belief policies use):
YOLO door model (doordetect_oi/best.pt) for doors, Grounding DINO (HTTP server) for directional signs and room-number plates,
with the same physical-size filters. It publishes what vlm_nav expects on /object_detector/output_detections:
Detection2DArray in frame "map"; per detection the pixel box (size/center in the 1280x960 colour image), class_id in
{door, directional sign, room label}, score and the 3D pose in the map frame (corner-mean position, normal-from-corners yaw
facing the camera -- the same convention as mm_dev/obj_det/detection.py). vlm_nav keeps doing its own room-number OCR and sign reading.

Inputs: /camera/color/image_raw (1280x960), /camera/depth/image_rect_raw (640x480 m, same FOV), written by rn_adapter.py.
"""
import base64, json, math, os, threading, time

import cv2
import numpy as np
import rclpy
import requests
from geometry_msgs.msg import Pose, PoseWithCovariance
from message_filters import ApproximateTimeSynchronizer, Subscriber
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from scipy.spatial.transform import Rotation as R
from sensor_msgs.msg import Image
from tf2_geometry_msgs import do_transform_pose
from tf2_ros import Buffer, TransformListener
from vision_msgs.msg import Detection2D, Detection2DArray, ObjectHypothesisWithPose

HFOV = 1.885
YOLO = "/home/user/yolo_ws/runs/doordetect_oi/weights/best.pt"
PROMPT = "a navigational sign. a directional sign with arrows. a room number plate."


class Swap(Node):
    def __init__(self):
        super().__init__("nano_owl_node")        # same node name as the original, so launch/log tooling still matches
        from ultralytics import YOLO as Y
        self.yolo = Y(YOLO)
        qos = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.rgb_sub = Subscriber(self, Image, "/camera/color/image_raw", qos_profile=qos)
        self.depth_sub = Subscriber(self, Image, "/camera/depth/image_rect_raw", qos_profile=qos)
        sync = ApproximateTimeSynchronizer([self.rgb_sub, self.depth_sub], 10, 0.2)
        sync.registerCallback(self.on_images)
        self.pub = self.create_publisher(Detection2DArray, "/object_detector/output_detections", 10)
        self.tfbuf = Buffer()
        TransformListener(self.tfbuf, self)
        self.hist = []                    # (label, xyz, t): a detection is published once it was seen twice within 1 m
        self.gd = []                      # latest Grounding DINO boxes for the frame pair they were computed on
        self.gd_frame = None
        self.lock = threading.Lock()
        threading.Thread(target=self.gdino_loop, daemon=True).start()
        self.get_logger().info("rn_detector_swap up (YOLO door + Grounding DINO signs/plates)")

    # ---------------------------------------------------------------- geometry
    @staticmethod
    def fx(w):
        return (w / 2.0) / math.tan(HFOV / 2.0)

    def point(self, depth, rgb_w, rgb_h, u, v):
        dh, dw = depth.shape[:2]
        du, dv = int(min(dw - 1, max(0, u * dw / rgb_w))), int(min(dh - 1, max(0, v * dh / rgb_h)))
        win = depth[max(0, dv - 1):dv + 2, max(0, du - 1):du + 2]
        win = win[np.isfinite(win) & (win > 0.3) & (win < 10.0)]
        if win.size == 0:
            return None
        z = float(np.median(win))
        f = self.fx(rgb_w)
        pc = ((u - rgb_w / 2.0) * z / f, (v - rgb_h / 2.0) * z / f, z)       # optical: x right, y down, z forward
        return np.array([pc[2], -pc[0], -pc[1]])                              # body: x forward, y left, z up

    def make(self, label, box, depth, rgb_w, rgb_h, score, tf, stamp):
        x1, y1, x2, y2 = box
        c = self.point(depth, rgb_w, rgb_h, (x1 + x2) / 2, (y1 + y2) / 2)
        if c is None:
            return None
        corners = [self.point(depth, rgb_w, rgb_h, px, py) for px, py in ((x1, y1), (x2, y1), (x2, y2), (x1, y2))]
        valid = [p for p in corners if p is not None]
        pos = c
        if label in ("door", "directional sign") and len(valid) >= 2:
            pos = np.mean(valid, axis=0)
        yaw = math.atan2(c[1], c[0])
        if all(p is not None for p in corners):
            nrm = np.cross(corners[1] - corners[0], corners[3] - corners[0])
            ln = np.linalg.norm(nrm)
            if np.isfinite(ln) and ln > 1e-6:
                nrm = nrm / ln
                if np.dot(nrm, -c) < 0:
                    nrm = -nrm
                yaw = math.atan2(nrm[1], nrm[0])
        # physical size filter (same as the rule/belief perception)
        if corners[0] is not None and corners[1] is not None and corners[3] is not None:
            wm, hm = float(np.linalg.norm(corners[1] - corners[0])), float(np.linalg.norm(corners[3] - corners[0]))
            clipped = y1 < 4 or y2 > rgb_h - 4 or x1 < 4 or x2 > rgb_w - 4
            if label == "door" and (not 0.45 <= wm <= 2.4 or (not clipped and not 1.4 <= hm <= 2.9)):
                return None
            if label == "directional sign" and not (0.45 <= wm <= 2.4 and 0.35 <= hm <= 2.4 and 0.55 <= hm / max(wm, 1e-3) <= 1.8):
                return None
            if label == "room label" and not 0.08 <= wm <= 0.6:
                return None
        pose = Pose()
        pose.position.x, pose.position.y, pose.position.z = float(pos[0]), float(pos[1]), float(pos[2])
        q = R.from_euler("z", yaw).as_quat()
        pose.orientation.x, pose.orientation.y, pose.orientation.z, pose.orientation.w = [float(v) for v in q]
        wp = do_transform_pose(pose, tf)
        return {"label": label, "box": box, "score": float(score), "pose": wp,
                "xyz": np.array([wp.position.x, wp.position.y, wp.position.z])}

    # ---------------------------------------------------------------- Grounding DINO in the background
    def gdino_loop(self):
        while rclpy.ok():
            time.sleep(1.0)
            with self.lock:
                fr = self.gd_frame
            if fr is None:
                continue
            rgb, depth, stamp = fr
            try:
                small = cv2.resize(rgb, (960, int(rgb.shape[0] * 960 / rgb.shape[1])))
                ok, buf = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 90])
                r = requests.post("http://127.0.0.1:8765/detect", json={"image": base64.b64encode(buf).decode(), "prompt": PROMPT,
                                                                        "box_thr": 0.3, "text_thr": 0.25}, timeout=10).json()
                k = rgb.shape[1] / 960.0
                dets = [(d["phrase"], [v * k for v in d["xyxy"]], d["score"]) for d in r.get("dets", [])]
                with self.lock:
                    self.gd = (stamp, dets)
            except Exception as e:  # noqa: BLE001
                self.get_logger().warn("gdino failed: %r" % e)

    # ---------------------------------------------------------------- main callback
    def on_images(self, rgb_msg, depth_msg):
        rgb = np.frombuffer(bytes(rgb_msg.data), np.uint8).reshape(rgb_msg.height, rgb_msg.width, 3)
        depth = np.frombuffer(bytes(depth_msg.data), np.float32).reshape(depth_msg.height, depth_msg.width)
        with self.lock:
            self.gd_frame = (rgb.copy(), depth.copy(), rgb_msg.header.stamp)
            gd = self.gd
        try:
            tf = self.tfbuf.lookup_transform("map", "realsense_link", rclpy.time.Time(), rclpy.duration.Duration(seconds=0.5))
        except Exception:  # noqa: BLE001
            return
        h, w = rgb.shape[:2]
        found = []
        res = self.yolo.predict(rgb, conf=0.2, imgsz=960, verbose=False)[0]      # the array is bgr8 already, which is what ultralytics expects (as in perception)
        for b in res.boxes:
            x1, y1, x2, y2 = [float(v) for v in b.xyxy[0]]
            bw, bh = x2 - x1, y2 - y1
            if bh < 40 or bh / max(bw, 1) < 1.1 or bh / max(bw, 1) > 6:
                continue
            d = self.make("door", [x1, y1, x2, y2], depth, w, h, float(b.conf), tf, rgb_msg.header.stamp)
            if d:
                found.append(d)
        if gd:
            for ph, box, sc in gd[1]:
                lab = "directional sign" if "sign" in ph else ("room label" if "plate" in ph or "number" in ph else None)
                if lab is None:
                    continue
                d = self.make(lab, [float(min(max(v, 0), (w - 1) if i % 2 == 0 else (h - 1))) for i, v in enumerate(box)], depth, w, h, sc, tf, rgb_msg.header.stamp)
                if d:
                    found.append(d)
        out = Detection2DArray()
        out.header.stamp = rgb_msg.header.stamp
        out.header.frame_id = "map"
        now = time.time()
        self.hist = [x for x in self.hist if now - x[2] < 5.0]
        for d in found:
            seen = sum(1 for lab, p, t in self.hist if lab == d["label"] and np.linalg.norm(p - d["xyz"]) < 1.0)
            self.hist.append((d["label"], d["xyz"], now))
            if seen < 1 and d["label"] != "room label":      # needs one earlier sighting (plates are kept: they are read at once)
                continue
            det = Detection2D()
            det.header = out.header
            x1, y1, x2, y2 = d["box"]
            det.bbox.size_x, det.bbox.size_y = float(x2 - x1), float(y2 - y1)
            det.bbox.center.position.x, det.bbox.center.position.y = float((x1 + x2) / 2), float((y1 + y2) / 2)
            hyp = ObjectHypothesisWithPose()
            hyp.pose = PoseWithCovariance()
            hyp.pose.pose = d["pose"]
            hyp.hypothesis.class_id = d["label"]
            # vlm_nav drops room labels scored < 0.45 (a bar tuned for OWL-ViT / YOLO scores). Our boxes already passed Grounding DINO's own
            # threshold (0.3) and the physical-size filter, so they are handed over on the consumer's scale instead of being discarded by a
            # threshold that was calibrated for another detector.
            hyp.hypothesis.score = min(1.0, 0.5 + d["score"]) if d["label"] in ("room label", "directional sign") else d["score"]
            det.results.append(hyp)
            out.detections.append(det)
        self.pub.publish(out)


def main():
    rclpy.init()
    rclpy.spin(Swap())


if __name__ == "__main__":
    main()
