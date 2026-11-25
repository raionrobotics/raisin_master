#!/usr/bin/env python3
"""Multi-camera perception for the room finder.

Three OAK-D Pro W (front / left / right, 90 deg apart) feed:
  * doors      : YOLO (yolo_ws/runs/doordetect_oi, single class `door`) -> 3D position from depth -> door registry
  * room plates: for a door near enough, the pixels whose 3D points lie close to the door are cut out of the
                 colour image (everything farther than `plate_radius` from the door is blanked), and a VLM reads
                 the room number from that crop.  Grounding DINO "room number plate" boxes give a second route.
  * signs      : Grounding DINO ("navigational sign") -> plane fit on the depth crop (centroid + surface normal,
                 as in "Sign Language: Towards Sign Understanding for Robot Autonomy") -> VLM parses
                 (place, direction) cues -> directions turned into world bearings with the sign normal.
Everything is published as JSON on /room_finder/registry for the navigator, plus /room_finder/debug_image.
"""
import json
import math
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import cv2
import numpy as np
import rclpy
import requests
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Image
from std_msgs.msg import String
from tf2_ros import Buffer, TransformListener

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from mm_dev.room_finder import camera_rig as rig  # noqa: E402
from mm_dev.room_finder import roomno  # noqa: E402
from mm_dev.room_finder.vlm import VLM, direction_offset, direction_turn  # noqa: E402

DEFAULT_YOLO = "/home/user/yolo_ws/runs/doordetect_oi/weights/best.pt"


def fit_plane(pts):
    c = pts.mean(0)
    _, s, vt = np.linalg.svd(pts - c, full_matrices=False)
    return c, vt[2], float(s[2] / math.sqrt(len(pts)))


class RoomPerception(Node):
    def __init__(self):
        super().__init__("room_perception")
        d = self.declare_parameter
        d("yolo_weights", DEFAULT_YOLO); d("yolo_conf", 0.2); d("yolo_imgsz", 960); d("detect_hz", 4.0)
        d("gdino_url", "http://127.0.0.1:8765"); d("gdino_hz", 1.0); d("gdino_width", 1280); d("gdino_workers", 1)
        d("read_range", 10.0); d("min_door_px", 70); d("plate_radius", 1.6); d("max_reads_per_door", 6)
        d("sign_ocr_words", 4); d("pose_at_stamp", True); d("door_protrude_max", 0.30); d("door_min_width", 0.6); d("door_merge", True); d("door_filter", True)
        d("sign_range", 10.0); d("sign_min_px", 110); d("sign_max_angle_deg", 135.0)
        d("det_range", 0.0); d("label_nearest_door", False); d("door_min_valid", 0.0); d("dark_enhance", 0.0); d("sign_overwrite", False); d("ocr_url", ""); d("ocr_min_conf", 0.9); d("gdino_plates", True); d("sign_crop_mx", 0.08); d("ocr_verify", False)   # min fraction of the door box with valid depth (0 = off; glass has almost none)
        d("out_dir", ""); d("record_dir", "")
        g = lambda k: self.get_parameter(k).value  # noqa: E731
        self.PXS = rig.COLOR_W / 1280.0   # pixel thresholds below are specified at 1280 px width
        self.P = {k: g(k) for k in ("yolo_conf", "yolo_imgsz", "read_range", "min_door_px", "plate_radius",
                                     "max_reads_per_door", "sign_ocr_words", "pose_at_stamp", "door_protrude_max", "door_min_width", "door_merge", "door_filter", "sign_range", "sign_min_px", "sign_max_angle_deg", "door_min_valid", "label_nearest_door", "det_range", "dark_enhance", "sign_overwrite", "ocr_min_conf", "gdino_plates", "sign_crop_mx", "ocr_verify")}
        self.out_dir = g("out_dir") or os.path.expanduser("~/raisin_ws/log/room_finder/" + time.strftime("%Y%m%d_%H%M%S"))
        os.makedirs(self.out_dir + "/crops", exist_ok=True)
        self.record_dir = g("record_dir")
        if self.record_dir:
            os.makedirs(self.record_dir, exist_ok=True)
        # gdino_hz 0: no wait, each camera's newest frame is sent once, gdino_workers requests in flight (the server overlaps
        # their pre/post-processing with the GPU); gdino_width: frames are scaled to this width (match the engine)
        self.gdino_url, self.gdino_period = g("gdino_url"), (1.0 / g("gdino_hz") if g("gdino_hz") > 0 else 0.0)
        self.gdino_w, self._g_lock, self._g_sent, self._g_i = int(g("gdino_width")), threading.Lock(), {}, 0

        from ultralytics import YOLO
        self.yolo = YOLO(g("yolo_weights"))
        self.vlm = VLM()
        self.pool = ThreadPoolExecutor(max_workers=3)
        self.pending = 0
        self.lock = threading.RLock()
        self.tfbuf = Buffer(); self.tflis = TransformListener(self.tfbuf, self)

        self.frames, self.seen_seq = {}, {}
        qos = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
        for c in rig.CAMERAS:
            self.create_subscription(Image, f"/{c}/rgb", lambda m, c=c: self._on_rgb(c, m), qos)
            self.create_subscription(Image, f"/{c}/depth", lambda m, c=c: self._on_depth(c, m), qos)
        self.pub_reg = self.create_publisher(String, "/room_finder/registry", 5)
        self.pub_dbg = self.create_publisher(Image, "/room_finder/debug_image", 2)
        self.pub_ev = self.create_publisher(String, "/room_finder/events", 50)

        self.doors, self.labels, self.signs = [], [], []   # registries (guarded by self.lock)
        self.plate_tries = []                              # [x, y, attempts, last_t] of direct plate reads
        self.stats = {"frames": 0, "door_dets": 0, "plate_reads": 0, "sign_reads": 0, "vlm_calls": 0}
        self.annot = {c: [] for c in rig.CAMERAS}          # per-camera overlay items for the debug image
        self.last_record = {}
        self._lag_t = {}
        self.logf = open(self.out_dir + "/events.jsonl", "a")
        threading.Thread(target=self._detect_loop, args=(1.0 / g("detect_hz"),), daemon=True).start()
        for _ in range(max(1, int(g("gdino_workers"))) if self.gdino_period <= 0 else 1):
            threading.Thread(target=self._gdino_loop, daemon=True).start()
        # ocr_url: scene-text OCR server (ai_pc/ocr_server.py). Room-number-shaped texts become plate reads directly: GDINO missed
        # plates mounted next to a bigger company nameplate (11-10: T104 boxed in 1 of 4 frames the OCR read it in)
        self.ocr_url, self._o_lock, self._o_sent, self._o_i = g("ocr_url"), threading.Lock(), {}, 0
        self.ocr_checks = []      # ocr_verify: one VLM check per OCR number and place (see _ocr_check)
        if self.ocr_url:
            threading.Thread(target=self._ocr_loop, daemon=True).start()
        self.create_timer(0.5, self._publish)
        self.get_logger().info("room_perception up: out_dir=%s yolo=%s" % (self.out_dir, g("yolo_weights")))

    # ------------------------------------------------------------------ io
    def _on_rgb(self, cam, m):
        img = np.frombuffer(bytes(m.data), np.uint8).reshape(m.height, m.width, 3)
        with self.lock:
            f = self.frames.setdefault(cam, {})
            stamp = rclpy.time.Time.from_msg(m.header.stamp) if self.P["pose_at_stamp"] and (m.header.stamp.sec or m.header.stamp.nanosec) else None
            pose = self.cam_pose(cam, stamp)
            if pose is None and stamp is not None:
                pose = self.cam_pose(cam)      # no transform at the image time: use the latest
            else:
                self._lag_probe(cam, stamp, pose)
            f.update(rgb=img, t_rgb=time.time(), seq=f.get("seq", 0) + 1, pose=pose)

    def _on_depth(self, cam, m):
        d = np.frombuffer(bytes(m.data), np.float32).reshape(m.height, m.width)
        with self.lock:
            self.frames.setdefault(cam, {}).update(depth=d, t_depth=time.time())

    def _log(self, kind, **kw):
        rec = {"t": round(time.time(), 2), "kind": kind, **kw}
        self.logf.write(json.dumps(rec) + "\n"); self.logf.flush()
        try:
            self.pub_ev.publish(String(data=json.dumps(rec)))   # VLM reads / sign parses, for the video recorder
        except Exception:  # noqa: BLE001
            pass

    def _lag_probe(self, cam, stamp, pose):
        """log how far the camera moved between the image time and the latest transform (rate limited)"""
        now = time.time()
        if stamp is None or pose is None or now - self._lag_t.get(cam, 0.0) < 20.0:
            return
        self._lag_t[cam] = now
        late = self.cam_pose(cam)
        if late is not None:
            self._log("pose_lag", cam=cam, moved=round(float(np.linalg.norm(late[1] - pose[1])), 3))

    def cam_pose(self, cam, stamp=None):
        """map <- camera body: (R, t) or None (stamp: the image time; default the latest transform)"""
        try:
            tf = self.tfbuf.lookup_transform("map", cam, stamp if stamp is not None else rclpy.time.Time())
        except Exception:  # noqa: BLE001
            return None
        q, tr = tf.transform.rotation, tf.transform.translation
        return rig.quat_to_rot((q.x, q.y, q.z, q.w)), np.array([tr.x, tr.y, tr.z])

    # ------------------------------------------------------------------ door pipeline
    def _detect_loop(self, period):
        while rclpy.ok():
            t0 = time.time()
            for cam in rig.CAMERAS:
                try:
                    self._process_cam(cam)
                except Exception as e:  # noqa: BLE001
                    self.get_logger().error("process %s: %r" % (cam, e))
            time.sleep(max(0.0, period - (time.time() - t0)))

    def _process_cam(self, cam):
        with self.lock:
            f = dict(self.frames.get(cam, {}))
        if "rgb" not in f or "depth" not in f or f["seq"] == self.seen_seq.get(cam):
            return
        if time.time() - f["t_rgb"] > 1.0:
            return
        pose = f.get("pose")   # camera pose when this image arrived, not the latest TF
        if pose is None:
            return
        self.seen_seq[cam] = f["seq"]
        rgb, depth = f["rgb"], f["depth"]
        R, t = pose
        self.stats["frames"] += 1
        self._maybe_record(cam, rgb, R, t)
        res = self.yolo.predict(rgb, conf=self.P["yolo_conf"], imgsz=self.P["yolo_imgsz"], verbose=False)[0]
        items = []
        for b in res.boxes:
            x1, y1, x2, y2 = [float(v) for v in b.xyxy[0]]
            conf = float(b.conf)
            bw, bh = x2 - x1, y2 - y1
            if bh < 40 * self.PXS or bh / max(bw, 1) < 1.1 or bh / max(bw, 1) > 6:
                continue
            z = rig.depth_at_color(depth, x1 + 0.3 * bw, y1 + 0.35 * bh, x2 - 0.3 * bw, y2 - 0.1 * bh)
            if z.size < 20:
                continue
            if self.P["door_min_valid"] > 0:   # glass doors / windows: the stereo depth inside the box is mostly missing
                cells = ((min(rig.DEPTH_W, int((x2 - 0.3 * bw) / rig.DEPTH_SCALE + 1)) - int(max(0, (x1 + 0.3 * bw) / rig.DEPTH_SCALE)))
                         * (min(rig.DEPTH_H, int((y2 - 0.1 * bh) / rig.DEPTH_SCALE + 1)) - int(max(0, (y1 + 0.35 * bh) / rig.DEPTH_SCALE))))
                if z.size < self.P["door_min_valid"] * max(cells, 1):
                    continue
            zc = float(np.median(z))
            if self.P["det_range"] > 0 and zc > self.P["det_range"]:
                continue    # farther than the detection range: ignored (position and size are least accurate there)
            pc = rig.pixel_to_body((x1 + x2) / 2, (y1 + y2) / 2 + 0.15 * bh, zc)
            pm = R @ pc + t
            nrm = self._wall_normal(depth, (x1, y1, x2, y2), zc, R)
            width_m = bw / rig.FX * zc
            height_m = bh / rig.FX * zc
            clipped = y1 < 4 or y2 > rig.COLOR_H - 4 or x1 < 4 or x2 > rig.COLOR_W - 4
            prot = self._protrusion(depth, (x1, y1, x2, y2), zc)
            if zc < 9.0:
                self._log("door_det", cam=cam, conf=round(conf, 2), w=round(width_m, 2), h=round(height_m, 2), z=round(zc, 2),
                          prot=None if prot is None else round(prot, 2), clipped=bool(clipped),
                          xy=[round(float(pm[0]), 2), round(float(pm[1]), 2)])
            # doors are ~0.8-1.3 m wide and ~2 m tall; furniture (racks, chairs) gets rejected here
            wmin = self.P["door_min_width"] if self.P["door_filter"] else 0.45
            if not (wmin <= width_m <= 2.4) or (not clipped and not (1.4 <= height_m <= 2.9)):
                continue
            # a door is flush with the wall around it; vending machines, benches and racks stand out of it
            if self.P["door_filter"] and prot is not None and prot > self.P["door_protrude_max"]:
                continue
            self.stats["door_dets"] += 1
            with self.lock:
                door = self._update_door(pm, conf, zc, width_m, nrm)
            items.append(("door", (x1, y1, x2, y2), "D%d %.2f" % (door["id"], conf)))
            self._maybe_read_door(door, cam, (x1, y1, x2, y2), zc, rgb, depth, pc, pm, R, t)
        with self.lock:
            self.annot[cam] = [it for it in self.annot[cam] if it[0] in ("sign", "ocr", "ocr_no", "ocr_wait") and time.time() - it[3] < 3.0] + \
                              [(k, bx, txt, time.time()) for k, bx, txt in items]

    def _protrusion(self, depth, box, zc):
        """How much nearer the box centre is than the surface just left and right of it (m); None if there is no side surface.
        About 0 for a door set in a wall, large for furniture standing in front of one."""
        x1, y1, x2, y2 = box
        bw, bh = x2 - x1, y2 - y1
        ya, yb = y1 + 0.2 * bh, y2 - 0.1 * bh
        sides = []
        for xa, xb in ((x1 - 0.30 * bw, x1 - 0.06 * bw), (x2 + 0.06 * bw, x2 + 0.30 * bw)):
            if xa < 0 or xb > rig.COLOR_W:
                continue
            z = rig.depth_at_color(depth, xa, ya, xb, yb)
            if z.size >= 12:
                sides.append(float(np.median(z)))
        if not sides:
            return None
        return min(sides) - zc if len(sides) == 1 else (sides[0] + sides[1]) / 2.0 - zc

    def _wall_normal(self, depth, box, zc, R):
        """Unit normal (map xy) of the wall plane around a box, pointing toward the camera; None if not planar."""
        x1, y1, x2, y2 = box
        bw, bh = x2 - x1, y2 - y1
        u0, u1 = int(max(0, x1 - 0.2 * bw) / rig.DEPTH_SCALE), int(min(rig.COLOR_W - 1, x2 + 0.2 * bw) / rig.DEPTH_SCALE)
        v0, v1 = int(max(0, y1) / rig.DEPTH_SCALE), int(min(rig.COLOR_H - 1, y2 - 0.1 * bh) / rig.DEPTH_SCALE)
        sub = depth[v0:v1 + 1, u0:u1 + 1]
        vv, uu = np.mgrid[v0:v1 + 1, u0:u1 + 1]
        ok = np.isfinite(sub) & (sub > 0.15) & (np.abs(sub - zc) < 0.4)
        if ok.sum() < 40:
            return None
        pts = rig.pixel_to_body(uu[ok] * rig.DEPTH_SCALE, vv[ok] * rig.DEPTH_SCALE, sub[ok])
        c, n, resid = fit_plane(pts[::max(1, len(pts) // 800)])
        if resid > 0.08:
            return None
        if float(n @ (-c)) < 0:
            n = -n
        nm = R @ n
        if abs(nm[2]) > 0.5:
            return None
        return (nm[:2] / np.linalg.norm(nm[:2])).tolist()

    def _update_door(self, pm, conf, dist, width_m, nrm=None):
        merge = self.P["door_merge"]
        rad = min(1.6, 0.8 + 0.1 * dist) if merge else 1.0       # far observations are projected less precisely
        w = 1.0 / max(dist, 1.0) ** 2 if merge else 1.0
        best, bd = None, 1e9
        for dr in self.doors:
            if dr.get("merged_into") is not None:
                continue
            d = math.hypot(dr["x"] - pm[0], dr["y"] - pm[1])
            if d < rad and d < bd:
                best, bd = dr, d
        if best is not None:
            dr = best
            ws = dr.get("ws", 1.0 / max(dr["best_dist"], 1.0) ** 2) if merge else dr["n"]
            dr["x"] = (dr["x"] * ws + pm[0] * w) / (ws + w); dr["y"] = (dr["y"] * ws + pm[1] * w) / (ws + w)
            dr["ws"] = ws + w
            dr["n"] += 1; dr["conf"] = max(dr["conf"], conf)
            dr["best_dist"] = min(dr["best_dist"], dist)
            if nrm is not None:
                dr["nrm"] = nrm
            return self._merge_doors(dr) if merge else dr
        dr = {"id": len(self.doors), "x": float(pm[0]), "y": float(pm[1]), "z": float(pm[2]), "n": 1, "conf": conf,
              "best_dist": dist, "width": width_m, "nrm": nrm, "attempts": 0, "last_dist": 1e9, "last_t": 0.0, "busy": False,
              "ws": w, "merged_into": None}
        self.doors.append(dr)
        return dr

    def _merge_doors(self, dr):
        """Fold other door entries that now lie on top of `dr` (the same door seen from several distances) into it."""
        for o in self.doors:
            if o is dr or o.get("merged_into") is not None:
                continue
            if math.hypot(o["x"] - dr["x"], o["y"] - dr["y"]) < 1.1:
                ws = dr["ws"] + o.get("ws", 1.0)
                dr["x"] = (dr["x"] * dr["ws"] + o["x"] * o.get("ws", 1.0)) / ws
                dr["y"] = (dr["y"] * dr["ws"] + o["y"] * o.get("ws", 1.0)) / ws
                dr["ws"] = ws
                dr["n"] += o["n"]; dr["conf"] = max(dr["conf"], o["conf"]); dr["best_dist"] = min(dr["best_dist"], o["best_dist"])
                dr["attempts"] = max(dr["attempts"], o["attempts"])
                dr["nrm"] = dr["nrm"] or o["nrm"]
                o["merged_into"] = dr["id"]
        return dr

    def _maybe_read_door(self, door, cam, box, dist, rgb, depth, pc, pm, R, t):
        with self.lock:
            if door["busy"] or dist > self.P["read_range"] or \
                    door["attempts"] >= self.P["max_reads_per_door"] + (6 if dist < 2.3 else 0):   # close-range re-reads allowed
                return
            if self._label_for_door(door) is not None:
                return
            if box[3] - box[1] < self.P["min_door_px"] * self.PXS:
                return
            if door["attempts"] > 0 and time.time() - door["last_t"] < 1.2:
                return
            if door["attempts"] >= 2 and dist > 0.85 * door["last_dist"] and time.time() - door["last_t"] < 10.0:
                return
            if self.pending >= 6:
                return
            door["busy"] = True; door["attempts"] += 1
            door["last_dist"], door["last_t"] = dist, time.time()
            self.pending += 1
        crop = self._door_crop(rgb, depth, box, pc)
        self.pool.submit(self._read_plate_job, door["id"], crop, dist, pm, "door")

    @staticmethod
    def _fit(img, target, cap=1280.0):
        """Scale so the long side is `target` px when smaller, and never above `cap` (4K crops would be huge VLM inputs)."""
        m = float(max(img.shape[:2]))
        s = target / m if m < target else (cap / m if m > cap else 1.0)
        return cv2.resize(img, None, fx=s, fy=s, interpolation=cv2.INTER_CUBIC if s > 1 else cv2.INTER_AREA) if s != 1.0 else img

    def _enhance(self, img, mask=None):
        """crops for the VLM whose median luma (over mask) is below dark_enhance: stretch the 1..99.5 % luma range and apply CLAHE.
        A dim corridor or a backlit door leaves a plate legible but nearly black, and the VLM then answers null."""
        thr = self.P["dark_enhance"]
        if thr <= 0 or img.size == 0:
            return img
        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        lum = lab[..., 0]
        vals = lum[mask] if mask is not None else lum
        if vals.size == 0:
            return img
        med = float(np.median(vals))
        if med >= thr:
            return img
        lo, hi = np.percentile(vals, 1), np.percentile(vals, 99.5)
        lab[..., 0] = np.clip((lum.astype(np.float32) - lo) * (255.0 / max(hi - lo, 8.0)), 0, 255).astype(np.uint8)
        lab[..., 0] = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(lab[..., 0])
        self._log("dark_enhance", median=round(med, 1), lo=round(float(lo), 1), hi=round(float(hi), 1))
        return cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)

    def _door_crop(self, rgb, depth, box, pc_door):
        """Colour crop around the door with everything farther than plate_radius (3D) from the door blanked."""
        x1, y1, x2, y2 = box
        bw, bh = x2 - x1, y2 - y1
        cx0, cx1 = int(max(0, x1 - 1.1 * bw)), int(min(rig.COLOR_W, x2 + 1.1 * bw))
        cy0, cy1 = int(max(0, y1 - 0.35 * bh)), int(min(rig.COLOR_H, y1 + 0.75 * bh))
        sub = rgb[cy0:cy1, cx0:cx1].copy()
        dep = cv2.resize(depth, (rig.COLOR_W, rig.COLOR_H), interpolation=cv2.INTER_NEAREST)[cy0:cy1, cx0:cx1]
        vv, uu = np.mgrid[cy0:cy1, cx0:cx1]
        z = np.where(np.isfinite(dep) & (dep > 0.1), dep, 0.0)
        p = rig.pixel_to_body(uu, vv, z)
        near = np.linalg.norm(p - pc_door, axis=-1) < self.P["plate_radius"]
        keep = near | (z == 0.0)
        sub = self._enhance(sub, keep)
        sub[~keep] = 127
        ys, xs = np.nonzero(keep)
        if ys.size:
            sub = sub[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
        return self._fit(sub, 640.0)

    def _read_plate_job(self, door_id, crop, dist, pm, source):
        try:
            num, conf, raw = self.vlm.read_plate(crop)
            self.stats["vlm_calls"] += 1
            tag = "%s_d%s_%d" % (source, door_id, int(time.time() * 10) % 100000)
            cname = "%s_%s.jpg" % (tag, num or "none")
            cv2.imwrite("%s/crops/%s" % (self.out_dir, cname), crop)
            self._log("plate_read", source=source, door=door_id, number=num, conf=conf, dist=round(dist, 2),
                      xy=[round(float(pm[0]), 2), round(float(pm[1]), 2)], raw=raw[:120], crop=cname)
            if num:
                self.stats["plate_reads"] += 1
                with self.lock:
                    self._add_label_read(pm, num, conf, dist, source)
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("plate read failed: %r" % e)
        finally:
            with self.lock:
                self.pending -= 1
                if source == "door" and 0 <= door_id < len(self.doors):
                    self.doors[door_id]["busy"] = False

    # ------------------------------------------------------------------ labels (room numbers)
    def _add_label_read(self, pm, num, conf, dist, source):
        w = conf * (1.6 if dist < 1.9 else 1.0 if dist < 2.5 else 0.7 if dist < 3.2 else 0.4)
        for lb in self.labels:
            d = math.hypot(lb["x"] - pm[0], lb["y"] - pm[1])
            # far reads project less precisely: accept the same number within a wider radius instead of splitting the plate
            same = any(n == num for n, _ in lb["reads"])
            if d < 1.5 or (same and d < 3.0) or (same and dist > 3.0 and d < min(3.5, 1.5 + 0.3 * (dist - 3.0))):
                lb["reads"].append((num, w)); lb["xs"].append(pm[0]); lb["ys"].append(pm[1])
                lb["x"], lb["y"] = float(np.median(lb["xs"])), float(np.median(lb["ys"]))
                return
        self.labels.append({"id": len(self.labels), "x": float(pm[0]), "y": float(pm[1]), "reads": [(num, w)],
                            "xs": [float(pm[0])], "ys": [float(pm[1])]})

    def _prefix_consensus(self):
        """Most common letters + 2-digit prefix among all reads once at least 3 reads exist (e.g. '30', 'T13')."""
        pre = {}
        for lb in self.labels:
            for n, _ in lb["reads"]:
                pre[roomno.key(n)] = pre.get(roomno.key(n), 0) + 1
        if sum(pre.values()) < 3:
            return None
        return max(pre.items(), key=lambda kv: kv[1])[0]

    def _label_number(self, lb):
        """(number, score): accepted when two reads agree and no other number is anywhere near as supported."""
        score, count = {}, {}
        cons = self._prefix_consensus()
        for n, w in lb["reads"]:
            if cons is not None and roomno.key(n) != cons:
                w *= 0.35
            score[n] = score.get(n, 0.0) + w
            count[n] = count.get(n, 0) + 1
        if not score:
            return None, 0.0
        n, sc = max(score.items(), key=lambda kv: kv[1])
        runner = max([v for k, v in score.items() if k != n], default=0.0)
        return (n, sc) if count[n] >= 2 and sc >= 1.0 and sc >= 2 * runner else (None, sc)

    def _label_for_door(self, door):
        for lb in self.labels:
            dd = math.hypot(lb["x"] - door["x"], lb["y"] - door["y"])
            if dd < 1.8:
                if self.P["label_nearest_door"] and any(
                        o is not door and o.get("merged_into") is None and
                        math.hypot(lb["x"] - o["x"], lb["y"] - o["y"]) < dd for o in self.doors):
                    continue    # a plate belongs to one door: its nearest one, not every false/duplicate door around it
                n, s = self._label_number(lb)
                if n:
                    return n
        return None

    # ------------------------------------------------------------------ Grounding DINO: signs (+ plates)
    def _gdino_loop(self):
        i = 0
        prompt = "a navigational sign. a directional sign with arrows. a room number plate."
        while rclpy.ok():
            if self.gdino_period > 0:
                time.sleep(self.gdino_period)
                cam = rig.CAMERAS[i % 3]; i += 1
            else:
                cam = self._gdino_next()
                if cam is None:
                    time.sleep(0.01)
                    continue
            with self.lock:
                f = dict(self.frames.get(cam, {}))
            if "rgb" not in f or "depth" not in f or time.time() - f["t_rgb"] > 1.0:
                continue
            pose = f.get("pose")
            if pose is None:
                continue
            try:
                k = rig.COLOR_W / float(self.gdino_w)
                small = cv2.resize(f["rgb"], (self.gdino_w, int(round(rig.COLOR_H / k))), interpolation=cv2.INTER_AREA) if k > 1.0 else f["rgb"]
                ok, buf = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 90])
                import base64
                r = requests.post(self.gdino_url + "/detect", json={"image": base64.b64encode(buf).decode(), "prompt": prompt,
                                                                     "box_thr": 0.3, "text_thr": 0.25}, timeout=10).json()
                for det in r.get("dets", []):
                    det["xyxy"] = [v * k for v in det["xyxy"]]
                    self._handle_gdino(cam, f["rgb"], f["depth"], pose, det)
            except Exception as e:  # noqa: BLE001
                self.get_logger().warn("gdino: %r" % e)

    def _gdino_next(self):
        """round robin over the cameras, skipping one whose newest frame was already sent (or is stale / has no depth yet)"""
        with self._g_lock:
            n = len(rig.CAMERAS)
            for j in range(n):
                cam = rig.CAMERAS[(self._g_i + j) % n]
                with self.lock:
                    f = self.frames.get(cam, {})
                    ok = "rgb" in f and "depth" in f and time.time() - f["t_rgb"] <= 1.0 and f["seq"] != self._g_sent.get(cam)
                    seq = f.get("seq")
                if ok:
                    self._g_sent[cam], self._g_i = seq, (self._g_i + j + 1) % n
                    return cam
        return None

    def _ocr_next(self):
        """round robin over the cameras, skipping one whose newest frame was already OCR'd (or is stale / has no depth or pose)"""
        with self._o_lock:
            n = len(rig.CAMERAS)
            for j in range(n):
                cam = rig.CAMERAS[(self._o_i + j) % n]
                with self.lock:
                    f = self.frames.get(cam, {})
                    ok = ("rgb" in f and "depth" in f and f.get("pose") is not None and time.time() - f["t_rgb"] <= 1.0
                          and f["seq"] != self._o_sent.get(cam))
                    seq = f.get("seq")
                if ok:
                    self._o_sent[cam], self._o_i = seq, (self._o_i + j + 1) % n
                    return cam
        return None

    def _ocr_loop(self):
        sess, warn_t = requests.Session(), 0.0
        while rclpy.ok():
            cam = self._ocr_next()
            if cam is None:
                time.sleep(0.02)
                continue
            with self.lock:
                f = dict(self.frames.get(cam, {}))
            rgb = np.ascontiguousarray(f["rgb"])
            try:
                r = sess.post(self.ocr_url + "/ocr", data=rgb.tobytes(), timeout=15,
                              headers={"X-Width": str(rgb.shape[1]), "X-Height": str(rgb.shape[0]), "Content-Type": "application/octet-stream"}).json()
            except Exception as e:  # noqa: BLE001
                if time.time() - warn_t > 30.0:
                    warn_t = time.time()
                    self.get_logger().warn("ocr server %s: %r" % (self.ocr_url, e))
                time.sleep(1.0)
                continue
            for it in r.get("items", []):
                try:
                    self._handle_ocr(cam, rgb, f["depth"], f["pose"], it)
                except Exception as e:  # noqa: BLE001
                    self.get_logger().warn("ocr item: %r" % e)

    def _ocr_number(self, text):
        """room number from an OCR text ('T 104', 'T1O4' -> 'T104'), None if it is not one. A bare number is dropped while the plates
        read so far carry a letter prefix: the OCR sometimes reads the 'T' as '1' or 'L' ('1117' / 'L111' for T117 / T111)."""
        t = re.sub(r"[\s.\-_:]", "", text.upper())
        m = re.match(r"^([A-Z]{0,2})([0-9OIL]{3,5})$", t)
        if not m:
            return None
        n = roomno.norm(m.group(1) + m.group(2).replace("O", "0").replace("I", "1").replace("L", "1"))
        p = roomno.parse(n) if n else None
        if p is None or not (3 <= len(str(p[1])) <= 5):
            return None
        if not p[0]:
            cons = self._prefix_consensus()
            if cons and re.match(r"[A-Z]", cons):
                return None
        return n

    def _handle_ocr(self, cam, rgb, depth, pose, it):
        if it["conf"] < self.P["ocr_min_conf"]:
            return
        with self.lock:
            num = self._ocr_number(it["text"])
        if num is None:
            return
        x1, y1, x2, y2 = it["box"]
        bw, bh = x2 - x1, y2 - y1
        z = rig.depth_at_color(depth, x1 - 0.5 * bw, y1 - 0.5 * bh, x2 + 0.5 * bw, y2 + 0.5 * bh)   # the plate around the text
        if z.size < 3:
            return
        zc = float(np.median(z))
        if zc > self.P["read_range"] or (self.P["det_range"] > 0 and zc > self.P["det_range"]):
            return
        R, t = pose
        pm = R @ rig.pixel_to_body((x1 + x2) / 2, (y1 + y2) / 2, zc) + t
        check = "off"
        if self.P["ocr_verify"]:
            check, e = self._ocr_check(num, pm, float(it["conf"]), zc)
            if e is not None:
                self.pool.submit(self._ocr_verify_job, e, self._context_crop(rgb, (x1, y1, x2, y2)), zc)
        with self.lock:
            if check in ("off", "ok"):
                self._add_label_read(pm, num, float(it["conf"]), zc, "ocr")
                self.annot[cam].append(("ocr", (x1, y1, x2, y2), "%s %.1fm" % (num, zc), time.time()))   # debug image: cyan
            else:   # waiting for the VLM: white "T113 ?", rejected: grey "2026 x"
                self.annot[cam].append(("ocr_no" if check == "no" else "ocr_wait", (x1, y1, x2, y2),
                                        "%s %s" % (num, "x" if check == "no" else "?"), time.time()))
        if check in ("off", "ok"):
            self.stats["plate_reads"] += 1
        self._log("ocr_read", cam=cam, number=num, text=it["text"], conf=it["conf"], dist=round(zc, 2), xy=[round(float(pm[0]), 2), round(float(pm[1]), 2)],
                  check=check)

    def _ocr_check(self, num, pm, conf, zc):
        """ocr_verify: an OCR room number counts once the VLM, shown the frame around it, calls it a room plate. One check per number
        and place (the same number within 3 m); reads wait for it ('held') and are dropped when it says no. 11-10: '2026' on a
        poster at the start and the 0119 of an emergency phone sticker became rooms. A check that did not settle (API error, the VLM
        read other digits) is repeated on a read >= 2 s later, a 'no' only from a view < 0.7 x as far; at most 3 checks per entry.
        A number the door / plate VLM reads already gave the label there needs no check.
        -> (this read: 'ok' / 'held' / 'no', the entry to check now or None)"""
        now = time.time()
        with self.lock:
            e = next((c for c in self.ocr_checks if c["num"] == num and math.hypot(c["x"] - pm[0], c["y"] - pm[1]) < 3.0), None)
            if e is None:
                e = {"id": len(self.ocr_checks), "num": num, "x": float(pm[0]), "y": float(pm[1]), "state": None, "tries": 0,
                     "t": 0.0, "dist": 1e9, "held": []}
                self.ocr_checks.append(e)
                if any(math.hypot(lb["x"] - pm[0], lb["y"] - pm[1]) < 1.5 and self._label_number(lb)[0] == num for lb in self.labels):
                    e["state"] = "ok"
            if e["state"] == "ok":
                return "ok", None
            e["held"] = (e["held"] + [(pm, conf, zc)])[-30:]
            go = (e["state"] in (None, "no") and e["tries"] < 3 and self.pending < 6 and now - e["t"] > 2.0
                  and (e["state"] is None or zc < 0.7 * e["dist"]))
            if not go:
                return ("no" if e["state"] == "no" else "held"), None
            e["state"], e["tries"], e["t"], e["dist"] = "busy", e["tries"] + 1, now, zc
            self.pending += 1
            return "held", e

    def _context_crop(self, rgb, box):
        """the frame around an OCR text box (>= 3 box widths each side), the box drawn in red, for verify_room_number"""
        x1, y1, x2, y2 = box
        bw, bh = x2 - x1, y2 - y1
        s = max(3.0 * max(bw, 1.6 * bh), 300.0 * rig.COLOR_W / 4032.0)
        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
        a, b = int(max(0, cx - s)), int(min(rig.COLOR_W, cx + s))
        c, d = int(max(0, cy - 0.8 * s)), int(min(rig.COLOR_H, cy + 0.8 * s))
        crop = self._enhance(rgb[c:d, a:b].copy())
        th = max(2, int(round(s / 120)))
        cv2.rectangle(crop, (int(x1 - a - th), int(y1 - c - th)), (int(x2 - a + th), int(y2 - c + th)), (0, 0, 255), th)
        return self._fit(crop, 640.0, 1024.0)

    def _ocr_verify_job(self, e, crop, zc):
        res, what, raw = None, "", ""
        try:
            res, what, raw = self.vlm.verify_room_number(crop, e["num"])
            self.stats["vlm_calls"] += 1
        except Exception as ex:  # noqa: BLE001
            what = "error %r" % ex
            self.get_logger().warn("ocr verify failed: %r" % ex)
        with self.lock:
            self.pending -= 1
            if what.startswith("error"):
                e["tries"] -= 1          # API trouble is not a verdict
            e["state"] = {True: "ok", False: "no"}.get(res)
            held = e["held"] if res is not None else []
            if res is not None:
                e["held"] = []
            if res is True:
                for pm, conf, dist in held:
                    self._add_label_read(pm, e["num"], conf, dist, "ocr")
                self.stats["plate_reads"] += len(held)
        cname = "ocrv_%s_c%d_%d_%s.jpg" % (e["num"], e["id"], e["tries"], {True: "ok", False: "no"}.get(res, "unk"))
        cv2.imwrite("%s/crops/%s" % (self.out_dir, cname), crop)
        self._log("ocr_verify", check=e["id"], number=e["num"], ok=res, what=what, tries=e["tries"], dist=round(zc, 2), reads=len(held),
                  xy=[round(e["x"], 2), round(e["y"], 2)], raw=raw[:160], crop=cname)

    def _handle_gdino(self, cam, rgb, depth, pose, det):
        x1, y1, x2, y2 = det["xyxy"]
        bw, bh = x2 - x1, y2 - y1
        ph = det["phrase"].lower()
        if bw < 8 or bh < 8 or bw * bh > 0.45 * rig.COLOR_W * rig.COLOR_H:
            return
        R, t = pose
        is_plate = ("plate" in ph or "number" in ph) and "sign" not in ph
        is_sign = "sign" in ph
        if not (is_plate or is_sign):
            return
        z = rig.depth_at_color(depth, x1, y1, x2, y2)
        if z.size < 15:
            return
        zc = float(np.median(z))
        if self.P["det_range"] > 0 and zc > self.P["det_range"]:
            return
        wm, hm = bw / rig.FX * zc, bh / rig.FX * zc
        self._log("gdino", cam=cam, phrase=ph, score=round(det["score"], 2), w_m=round(wm, 2), h_m=round(hm, 2), z=round(zc, 2))
        # navigational signs are ~1 m panels; anything smaller with a "sign" phrase is a nameplate / dispenser
        panel = 0.45 <= wm <= 2.4 and 0.35 <= hm <= 2.4 and 0.55 <= hm / max(wm, 1e-3) <= 1.8
        strip = 0.25 <= wm <= 2.4 and 0.05 <= hm <= 0.6 and hm / max(wm, 1e-3) < 0.55   # e.g. a 40x10 cm "<- T131~T150" sign
        if is_plate and strip and wm >= 0.3:   # too long for a door plate: a range / arrow strip, parse it as a sign
            is_sign, is_plate = True, False
        if is_sign and not (panel or strip):
            is_sign, is_plate = False, (0.08 <= wm <= 0.6)
        if is_plate and not (0.08 <= wm <= 0.6):
            return
        if is_plate and self.P["gdino_plates"]:     # gdino_plates False: plates come from the OCR only (strips above still become signs)
            self._handle_plate_box(cam, rgb, (x1, y1, x2, y2), zc, R, t)
        elif is_sign and bw >= self.P["sign_min_px"] * self.PXS * 0.6 and zc <= self.P["sign_range"] + 2:
            self._handle_sign_box(cam, rgb, depth, (x1, y1, x2, y2), zc, R, t)

    def _handle_plate_box(self, cam, rgb, box, zc, R, t):
        x1, y1, x2, y2 = box
        if (x2 - x1) < 26 * self.PXS or zc > self.P["read_range"]:
            return
        pc = rig.pixel_to_body((x1 + x2) / 2, (y1 + y2) / 2, zc)
        pm = R @ pc + t
        with self.lock:
            for lb in self.labels:
                if math.hypot(lb["x"] - pm[0], lb["y"] - pm[1]) < 1.5 and self._label_number(lb)[0]:
                    return
            for nx, ny, cnt, last in self.plate_tries:
                if math.hypot(nx - pm[0], ny - pm[1]) < 1.0 and (cnt >= (8 if zc < 2.3 else 2) or time.time() - last < (3.0 if zc < 2.3 else 8.0)):
                    return
            if self.pending >= 6:
                return
            self.pending += 1
            self.annot[cam].append(("plate", box, "plate", time.time()))
            for e in self.plate_tries:
                if math.hypot(e[0] - pm[0], e[1] - pm[1]) < 1.0:
                    e[2] += 1; e[3] = time.time(); break
            else:
                self.plate_tries.append([float(pm[0]), float(pm[1]), 1, time.time()])
        m = 0.35
        bw, bh = x2 - x1, y2 - y1
        crop = rgb[int(max(0, y1 - m * bh)):int(min(rig.COLOR_H, y2 + m * bh)), int(max(0, x1 - m * bw)):int(min(rig.COLOR_W, x2 + m * bw))].copy()
        crop = self._enhance(self._fit(crop, 400.0))
        self.pool.submit(self._read_plate_job, -1, crop, zc, pm, "plate")

    def _handle_sign_box(self, cam, rgb, depth, box, zc, R, t):
        x1, y1, x2, y2 = box
        bw = x2 - x1
        # plane fit on the depth pixels inside the box (paper: least squares on the sign's depth crop)
        u0, u1 = int((x1 + 0.1 * bw) / rig.DEPTH_SCALE), int((x2 - 0.1 * bw) / rig.DEPTH_SCALE)
        v0, v1 = int((y1 + 0.1 * (y2 - y1)) / rig.DEPTH_SCALE), int((y2 - 0.1 * (y2 - y1)) / rig.DEPTH_SCALE)
        sub = depth[max(0, v0):v1 + 1, max(0, u0):u1 + 1]
        vv, uu = np.mgrid[max(0, v0):v1 + 1, max(0, u0):u1 + 1]
        ok = np.isfinite(sub) & (sub > 0.15) & (np.abs(sub - zc) < 0.5)
        if ok.sum() < 30:
            return
        pts = rig.pixel_to_body(uu[ok] * rig.DEPTH_SCALE, vv[ok] * rig.DEPTH_SCALE, sub[ok])
        c, n, resid = fit_plane(pts[::max(1, len(pts) // 800)])
        if resid > 0.06:
            return
        if float(n @ (-c)) < 0:
            n = -n
        head_on = math.degrees(math.acos(max(-1.0, min(1.0, float(n @ (-c / np.linalg.norm(c)))))))
        cm, nm = R @ c + t, R @ n
        nxy = nm[:2] / max(1e-6, np.linalg.norm(nm[:2]))
        if abs(nm[2]) > 0.5:      # not a wall-mounted (vertical) sign
            return
        with self.lock:
            sg = None
            for s in self.signs:
                if math.hypot(s["x"] - cm[0], s["y"] - cm[1]) < 1.2 and float(np.dot(s["n"], nxy)) > 0.5:
                    sg = s
                    break
            if sg is None and head_on > self.P["sign_max_angle_deg"]:
                return      # an oblique view gives a wrong plane normal (the arrow bearing follows it): do not register a sign from it
            if sg is None:
                sg = {"id": len(self.signs), "x": float(cm[0]), "y": float(cm[1]), "z": float(cm[2]), "n": nxy.tolist(),
                      "n_obs": 0, "best_q": 0.0, "reads": 0, "empty": 0, "cues": [], "busy": False,
                      "text_ok": None, "ocr_tries": 0, "ocr_busy": False}
                self.signs.append(sg)
            sg["n_obs"] += 1
            self.annot[cam].append(("sign", box, "S%d %.0f deg %.1fm" % (sg["id"], head_on, zc), time.time()))
            q = (bw / rig.COLOR_W) * math.cos(math.radians(head_on))
            ex = max(0.0, self.P["sign_crop_mx"] - 0.08) * bw   # the wider crop must fit in the image too
            good = (head_on <= self.P["sign_max_angle_deg"] and bw >= self.P["sign_min_px"] * self.PXS and zc <= self.P["sign_range"]
                    and x1 - ex > 4 and x2 + ex < rig.COLOR_W - 4)     # a sign cut by the image edge loses entries (e.g. only "T122" of "T122  T127")
            if sg["empty"] >= 2 and not sg["cues"]:
                return          # parsed twice, nothing on it: not a navigational sign
            if self.P["sign_ocr_words"] > 0 and sg["text_ok"] is not True:
                if sg["text_ok"] is None and good and not sg["ocr_busy"] and self.pending < 6:
                    sg["ocr_busy"] = True
                    mm = 0.08
                    bh0 = y2 - y1
                    oc = rgb[int(max(0, y1 - mm * bh0)):int(min(rig.COLOR_H, y2 + mm * bh0)), int(max(0, x1 - mm * bw)):int(min(rig.COLOR_W, x2 + mm * bw))].copy()
                    self.pool.submit(self._ocr_job, sg["id"], self._fit(oc, 900.0))
                return
            if not good or sg["busy"] or sg["reads"] >= 6 or (sg["cues"] and q < (0.8 if (self.P["sign_overwrite"] and sg.get("unconfirmed")) else 1.3) * sg["best_q"]) or self.pending >= 6:
                return
            sg["busy"] = True; self.pending += 1
            sid = sg["id"]
        # sign_crop_mx: left / right margin (fraction of the box width). GDINO boxes hug the text and cut the arrow at the strip's end
        # (11-10 18:40: the bent arrow of 'T112~T121' was half cut and read as plain 'left')
        m, mx = 0.08, self.P["sign_crop_mx"]
        bh = y2 - y1
        crop = rgb[int(max(0, y1 - m * bh)):int(min(rig.COLOR_H, y2 + m * bh)), int(max(0, x1 - mx * bw)):int(min(rig.COLOR_W, x2 + mx * bw))].copy()
        crop = self._enhance(self._fit(crop, 900.0))
        nview = -nxy  # direction a person facing the sign looks in
        self.pool.submit(self._parse_sign_job, sid, crop, q, head_on, math.atan2(nview[1], nview[0]), zc)

    def _ocr_job(self, sid, crop):
        """Count legible words on a sign candidate (the sign-understanding paper filters with OCR the same way)."""
        try:
            import pytesseract
            g = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
            d = pytesseract.image_to_data(g, output_type=pytesseract.Output.DICT, config="--psm 11")
            nw = sum(1 for w, c in zip(d["text"], d["conf"]) if float(c) >= 60 and sum(ch.isalpha() for ch in w) >= 3)
            # arrow / range strips ("<- T131~T150") have no long words: a room-number-like token is enough
            num = any(float(c) >= 40 and re.search(r"\d{2,}", w) for w, c in zip(d["text"], d["conf"]))
            with self.lock:
                sg = self.signs[sid]
                sg["ocr_tries"] += 1
                if nw >= self.P["sign_ocr_words"] or num:
                    sg["text_ok"] = True
                elif sg["ocr_tries"] >= 3:
                    sg["text_ok"] = False         # three good views and still no text: not a sign
            self._log("sign_ocr", sign=sid, words=nw, ok=self.signs[sid]["text_ok"])
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("sign ocr failed: %r" % e)
            with self.lock:
                self.signs[sid]["text_ok"] = True   # no OCR available: fall back to the old behaviour
        finally:
            with self.lock:
                self.signs[sid]["ocr_busy"] = False

    @staticmethod
    def _cue_key(c):
        words = re.sub(r"[^a-z ]", " ", c["place"].lower()).split()
        return " ".join(words[:2] if words[:1] == ["stair"] else words[:1]) + "|" + "-".join(re.findall(r"\d{3,}", c["place"]))   # "T101~T104" and "T105~T109" are different entries

    def _overwrite_cues(self, sid, sg, q, cues):
        """sign_overwrite: an entry read the same way twice is kept; the other entries come from one reference read -- the latest one
        when its view is at least 0.6 x the best view so far, else the best one. A misread ("T135-T150", "101~110" for T131~T150) is
        replaced by a later comparable read instead of piling up next to the right entry. Called with self.lock held."""
        hist = sg.setdefault("cue_hist", [])
        hist.append((q, [c for c in cues if c.get("bearing") is not None]))
        count = {}
        for _, cs in hist:
            for k in {self._cue_key(c) for c in cs}:
                count[k] = count.get(k, 0) + 1
        best = max(hist, key=lambda h: h[0])
        ref = hist[-1] if hist[-1][0] >= 0.6 * best[0] else best
        keep = {}
        for qq, cs in hist:                       # confirmed entries: the cue from the best view that showed them
            for c in cs:
                k = self._cue_key(c)
                if count[k] >= 2 and (k not in keep or qq > keep[k][0]):
                    keep[k] = (qq, c)
        for c in ref[1]:
            keep.setdefault(self._cue_key(c), (ref[0], c))
        before = [c["place"] for c in sg.get("cues", [])]
        sg["cues"] = [v[1] for v in keep.values()]
        sg["unconfirmed"] = any(count[self._cue_key(c)] < 2 for c in sg["cues"])   # re-read sooner until a second read agrees
        dropped = [p for p in before if p not in [c["place"] for c in sg["cues"]]]
        if dropped:
            self._log("sign_overwrite", sign=sid, dropped=dropped, kept=[c["place"] for c in sg["cues"]])

    def _parse_sign_job(self, sid, crop, q, head_on, view_yaw, dist):
        try:
            cues, raw = self.vlm.parse_sign(crop)
            self.stats["vlm_calls"] += 1
            cname = "sign_s%d_%d.jpg" % (sid, int(time.time() * 10) % 100000)
            cv2.imwrite("%s/crops/%s" % (self.out_dir, cname), crop)
            for c in cues:
                off = direction_offset(c["direction"])
                c["bearing"] = None if off is None else (view_yaw + off + math.pi) % (2 * math.pi) - math.pi
                off2 = direction_turn(c["direction"])     # bent arrow: the second leg
                c["bearing2"] = None if off2 is None else (view_yaw + off2 + math.pi) % (2 * math.pi) - math.pi
                c["view"] = round(float(view_yaw), 3)      # the direction a reader of the sign looks in
            self._log("sign_read", sign=sid, q=round(q, 3), head_on=round(head_on, 1), dist=round(dist, 2), cues=cues,
                      raw=str(raw)[:700], crop=cname)
            with self.lock:
                sg = self.signs[sid]
                sg["reads"] += 1
                usable = any(c.get("bearing") is not None for c in cues)   # all-"none" directions = oblique/unreadable view
                sg["empty"] += 0 if cues else 1
                if usable and self.P["sign_overwrite"]:
                    self._overwrite_cues(sid, sg, q, cues)
                elif usable:
                    # merge across reads: per destination keep the cue from the best-quality view that showed it, so a
                    # later read that missed an entry (partial / oblique view) cannot erase it
                    best = sg.setdefault("cue_best", {})
                    for c in cues:
                        if c.get("bearing") is None:
                            continue
                        key = self._cue_key(c)
                        if key not in best or q > best[key][0]:
                            best[key] = (q, c)
                    sg["cues"] = [v[1] for v in best.values()]
                    sg["best_q"], sg["view_yaw"] = max(sg["best_q"], q), view_yaw
                    self.stats["sign_reads"] += 1
        except Exception as e:  # noqa: BLE001
            self.get_logger().warn("sign parse failed: %r" % e)
        finally:
            with self.lock:
                self.pending -= 1
                self.signs[sid]["busy"] = False

    # ------------------------------------------------------------------ output
    def _maybe_record(self, cam, rgb, R, t):
        if not self.record_dir:
            return
        last = self.last_record.get(cam)
        if last is not None and time.time() - last[0] < 1.5 and np.linalg.norm(t - last[1]) < 0.4:
            return
        self.last_record[cam] = (time.time(), t.copy())
        stem = "%s/%s_%d" % (self.record_dir, cam, int(time.time() * 1000))
        cv2.imwrite(stem + ".jpg", rgb, [cv2.IMWRITE_JPEG_QUALITY, 92])
        np.save(stem + "_pose.npy", np.vstack([R, t]))

    def _publish(self):
        with self.lock:
            labels = []
            for lb in self.labels:
                n, s = self._label_number(lb)
                labels.append({"id": lb["id"], "x": lb["x"], "y": lb["y"], "number": n, "score": round(s, 2),
                               "reads": [[a, round(b, 2)] for a, b in lb["reads"]]})
            doors = [{"id": d["id"], "x": d["x"], "y": d["y"], "n": d["n"], "conf": round(d["conf"], 2),
                      "attempts": d["attempts"], "label": self._label_for_door(d), "nrm": d.get("nrm"),
                      "width": round(d["width"], 2)} for d in self.doors if d.get("merged_into") is None]
            signs = [{"id": s["id"], "x": s["x"], "y": s["y"], "n": s["n"], "reads": s["reads"], "cues": s["cues"],
                      "dead": bool((s["empty"] >= 2 and not s["cues"]) or s["text_ok"] is False),
                      "valid": s["text_ok"] is True or self.P["sign_ocr_words"] <= 0,
                      "best_q": round(s["best_q"], 3), "n_obs": s["n_obs"]} for s in self.signs]
            msg = {"t": time.time(), "doors": doors, "labels": labels, "signs": signs, "stats": dict(self.stats),
                   "pending": self.pending}
            annot = {c: list(v) for c, v in self.annot.items()}
            frames = {c: self.frames.get(c, {}).get("rgb") for c in rig.CAMERAS}
        self.pub_reg.publish(String(data=json.dumps(msg)))
        tiles = []
        for c in ("oak_left", "oak_front", "oak_right"):
            im = frames[c]
            if im is None:
                im = np.zeros((rig.COLOR_H, rig.COLOR_W, 3), np.uint8)
            im = im.copy()
            for kind, (x1, y1, x2, y2), txt, ts in annot[c]:
                if time.time() - ts > 3.0:
                    continue
                col = {"door": (0, 255, 0), "sign": (0, 200, 255), "plate": (255, 0, 255), "ocr": (255, 255, 0), "ocr_no": (128, 128, 128), "ocr_wait": (255, 255, 255)}[kind]
                cv2.rectangle(im, (int(x1), int(y1)), (int(x2), int(y2)), col, 3)
                cv2.putText(im, txt, (int(x1), max(20, int(y1) - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.9, col, 2)
            cv2.putText(im, c, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (255, 255, 255), 2)
            tiles.append(cv2.resize(im, (480, 360)))
        out = np.hstack(tiles)
        m = Image(); m.height, m.width, m.encoding, m.step = out.shape[0], out.shape[1], "bgr8", out.shape[1] * 3
        m.data = out.tobytes(); self.pub_dbg.publish(m)


def main():
    rclpy.init()
    node = RoomPerception()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
