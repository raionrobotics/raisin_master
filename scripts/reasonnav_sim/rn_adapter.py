#!/usr/bin/env python3
"""Adapter that lets the (modified) ReasonNav vlm_nav + OWL-ViT detector run on the raisin hospital simulation.

ReasonNav was written for one RealSense on a pan-tilt head; here it gets the FRONT OAK-D Pro W only.
  in : oak_front/rgb (4K bgr8), oak_front/depth (32FC1 m, 640x480)       [raisin_bridge]
  out: /camera/color/image_raw (resized), /camera/color/camera_info, /camera/depth/image_rect_raw, /camera/depth/camera_info,
       /camera/extrinsics/depth_to_color (identity: colour and depth share the optical centre and FOV),
       TF oak_front -> realsense_link (identity; both are x-forward/y-left/z-up), /joint_states (pan_joint = 0)
  monitor: /vlm_text "MISSION COMPLETE: Room X found at map (x, y)" -> <out_dir>/finder/result.json in the schema run_trials.py scores
           (also written with found=false when max_time runs out).
"""
import json, math, os, re, time

import cv2
import numpy as np
import rclpy
from geometry_msgs.msg import TransformStamped
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from realsense2_camera_msgs.msg import Extrinsics
from sensor_msgs.msg import CameraInfo, Image, JointState
from std_msgs.msg import String
from tf2_ros import Buffer, StaticTransformBroadcaster, TransformListener

HFOV = 1.885
COLOR_OUT = (1280, 960)


def info(w, h, frame):
    fx = (w / 2.0) / math.tan(HFOV / 2.0)
    m = CameraInfo()
    m.header.frame_id = frame
    m.width, m.height = w, h
    m.distortion_model = "plumb_bob"
    m.d = [0.0] * 5
    m.k = [fx, 0.0, w / 2.0, 0.0, fx, h / 2.0, 0.0, 0.0, 1.0]
    m.r = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    m.p = [fx, 0.0, w / 2.0, 0.0, 0.0, fx, h / 2.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    return m


class Adapter(Node):
    def __init__(self):
        super().__init__("rn_adapter")
        d = self.declare_parameter
        d("target", 0); d("out_dir", "/tmp/rn_out"); d("max_time", 900.0)
        g = lambda k: self.get_parameter(k).value  # noqa: E731
        self.target, self.out_dir, self.max_time = str(g("target")), g("out_dir"), float(g("max_time"))
        os.makedirs(self.out_dir + "/finder", exist_ok=True)
        self.t0 = time.time()
        be = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.create_subscription(Image, "oak_front/rgb", self.on_rgb, be)
        self.create_subscription(Image, "oak_front/depth", self.on_depth, be)
        # big frames (3.7 MB colour) are lost over best-effort UDP; a reliable publisher is still compatible with best-effort subscribers
        rel = QoSProfile(depth=2, reliability=ReliabilityPolicy.RELIABLE)
        self.pub_rgb = self.create_publisher(Image, "/camera/color/image_raw", rel)
        self.pub_depth = self.create_publisher(Image, "/camera/depth/image_rect_raw", rel)
        self.pub_ci = self.create_publisher(CameraInfo, "/camera/color/camera_info", be)
        self.pub_di = self.create_publisher(CameraInfo, "/camera/depth/camera_info", be)
        self.pub_ex = self.create_publisher(Extrinsics, "/camera/extrinsics/depth_to_color",
                                            QoSProfile(depth=1, reliability=ReliabilityPolicy.RELIABLE, durability=DurabilityPolicy.TRANSIENT_LOCAL,
                                                       history=HistoryPolicy.KEEP_LAST))
        ex = Extrinsics()
        ex.rotation = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
        ex.translation = [0.0, 0.0, 0.0]
        self.pub_ex.publish(ex)
        self.pub_js = self.create_publisher(JointState, "/joint_states", 10)
        self.static = StaticTransformBroadcaster(self)
        t = TransformStamped()
        t.header.stamp = self.get_clock().now().to_msg()
        t.header.frame_id, t.child_frame_id = "oak_front", "realsense_link"
        t.transform.rotation.w = 1.0
        self.static.sendTransform(t)
        self.create_subscription(String, "/vlm_text", self.on_text, 10)
        self.tfbuf = Buffer()
        TransformListener(self.tfbuf, self)
        self.path_len, self.last_xy, self.done = 0.0, None, False
        self.last_depth = None
        self.color_size = COLOR_OUT
        self.create_timer(0.2, self.tick)
        self.create_timer(1.0, self.slow)
        self.get_logger().info("rn_adapter up: target=%s out=%s" % (self.target, self.out_dir))

    def on_rgb(self, m):
        # colour and depth are rendered on independent 6 Hz clocks, further apart than the detector's 0.1 s approximate-time
        # window: publish the newest depth together with every colour frame, carrying the colour stamp (sim time, same base as TF)
        if self.last_depth is not None:
            dm = Image()
            dm.header = m.header
            dm.header.frame_id = "realsense_link"
            dm.height, dm.width, dm.encoding, dm.step, dm.is_bigendian = (self.last_depth.height, self.last_depth.width,
                                                                          self.last_depth.encoding, self.last_depth.step, self.last_depth.is_bigendian)
            dm.data = self.last_depth.data
            self.pub_depth.publish(dm)
        else:
            return
        img = np.frombuffer(bytes(m.data), np.uint8).reshape(m.height, m.width, 3)
        # frames wider than 1920 px (the 4K sim camera of the inject mode) are reduced: vlm_nav only needs light frames then
        small = cv2.resize(img, COLOR_OUT, interpolation=cv2.INTER_AREA) if m.width > 1920 else img
        self.color_size = (small.shape[1], small.shape[0])
        out = Image()
        out.header = m.header
        out.header.frame_id = "realsense_link"
        out.height, out.width, out.encoding, out.step = small.shape[0], small.shape[1], m.encoding, small.shape[1] * 3
        out.data = small.tobytes()
        self.pub_rgb.publish(out)

    def on_depth(self, m):
        self.last_depth = m

    def slow(self):
        ci = info(self.color_size[0], self.color_size[1], "realsense_link")
        di = info(640, 480, "realsense_link")
        now = self.get_clock().now().to_msg()
        ci.header.stamp = di.header.stamp = now
        self.pub_ci.publish(ci); self.pub_di.publish(di)
        js = JointState()
        js.header.stamp = now
        js.name, js.position = ["pan_joint", "tilt_joint"], [0.0, 0.0]
        self.pub_js.publish(js)
        self.pub_ex.publish(self._ex())

    @staticmethod
    def _ex():
        ex = Extrinsics()
        ex.rotation = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
        ex.translation = [0.0, 0.0, 0.0]
        return ex

    def robot_xy(self):
        try:
            t = self.tfbuf.lookup_transform("map", "base_link", rclpy.time.Time()).transform.translation
            return t.x, t.y
        except Exception:  # noqa: BLE001
            return None

    def tick(self):
        if self.done:
            return
        xy = self.robot_xy()
        if xy and self.last_xy:
            self.path_len += math.hypot(xy[0] - self.last_xy[0], xy[1] - self.last_xy[1])
        if xy:
            self.last_xy = xy
        if time.time() - self.t0 > self.max_time:
            self.finish(False, None)

    def on_text(self, m):
        mm = re.search(r"MISSION COMPLETE: Room (\S+) found at map \((-?[\d.]+), (-?[\d.]+)\)", m.data)
        if mm and not self.done:
            self.finish(True, (float(mm[2]), float(mm[3])), reading=mm[1])

    def finish(self, found, label_xy, reading=None):
        self.done = True
        rp = self.robot_xy() or self.last_xy
        res = {"target": self.target, "found": bool(found), "elapsed_s": round(time.time() - self.t0, 1),
               "robot_xy": None if rp is None else [round(rp[0], 2), round(rp[1], 2)], "path_len_m": round(self.path_len, 1),
               "label_xy": None if label_xy is None else [round(label_xy[0], 2), round(label_xy[1], 2)], "reading": reading,
               "n_labels": 0, "n_doors": 0, "signs": [], "stats": {}}
        json.dump(res, open(self.out_dir + "/finder/result.json", "w"), indent=1)
        self.get_logger().info("%s room %s after %.0f s, %.0f m" % ("FOUND" if found else "GAVE UP on", self.target, res["elapsed_s"], self.path_len))


def main():
    rclpy.init()
    rclpy.spin(Adapter())


if __name__ == "__main__":
    main()
