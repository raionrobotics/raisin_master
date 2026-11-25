#!/usr/bin/env python3
"""Real-robot fixes (2026-10-23), applied as exact-text edits so they merge with other sessions' changes:

  * time sync   : colour/depth frames carry their capture time (depthai steady clock -> this PC's clock); odometry stamps
                  (robot clock) are mapped with a running min(arrival - stamp) offset; depth is paired with the colour frame
                  it was taken with.
  * depth       : 1280x800 mono input, ROBOTICS preset, speckle + spatial filter, 0.2-8 m range cut, IR dot projector on,
                  exposure caps 8 ms (the 1 ms cap made the corridor images dark and noisy).
  * doors       : drop boxes whose depth is mostly missing (glass, windows); YOLO settings unchanged.
  * signs       : small strip signs ("<- T131~T150", ~40x10 cm) pass the size rule and are not read as plates; the OCR
                  gate also accepts a room-number-like token; sign_min_px 70 at 1280 px.

    patch_realrobot_20261023.py --rf ~/raisin_ws/scripts/room_finder_net --mmdev ~/ReasonNav/src/mm_dev [--dry-run]

Every anchor must occur exactly once; if any is missing nothing is written. Originals go to ~/room_finder_backup/<time>/."""
import argparse
import os
import shutil
import sys
import time

E = {}   # relative path -> [(old, new)]

# ---------------------------------------------------------------- oak_local.py
E["rf:ai_pc/oak_local.py"] = [
    ("""        self.rig, self.rl, self.stamp_host = rig, rosless, stamp_host
""", """        self.rig, self.rl, self.stamp_host = rig, rosless, stamp_host
        self.stamp = bool(rig.get("oak", {}).get("stamp", True)) or stamp_host   # frames carry their capture time
"""),
    ("""        self.stats, self.expo = {}, {}
""", """        self.stats, self.expo = {}, {}
        self.depth_buf, self.buf_lock, self._last_depth, self.pair_dt = {}, threading.Lock(), {}, {}
        self.mono2wall = time.time() - time.monotonic()   # depthai timestamps are steady_clock (= time.monotonic)
"""),
    ("""        dw, dh = int(dc["width"]), int(dc["height"])
""", """        dw, dh = int(dc["width"]), int(dc["height"])
        sc = self.rig.get("stereo", {})
        mono = (int(sc.get("width", 640)), int(sc.get("height", 400)))
"""),
    ("""            pipe, qc, qd = self._build(dai, dev, cw, ch, fps, dw, dh, oak)
""", """            pipe, qc, qd = self._build(dai, dev, cw, ch, fps, dw, dh, oak, mono)
"""),
    ("""    def _build(dai, dev, cw, ch, fps, dw, dh, oak):
""", """    def _build(dai, dev, cw, ch, fps, dw, dh, oak, mono=(640, 400)):
"""),
    ("""        lo = left.requestOutput((640, 400), dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
        ro = right.requestOutput((640, 400), dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
""", """        lo = left.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
        ro = right.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
""", "left.requestOutput(mono, dai.ImgFrame.Type.GRAY8"),
    ("""        st.build(lo, ro)
""", """        st.build(lo, ro)
        OakLocal._stereo_quality(dai, st, oak)
"""),
    ("""    @staticmethod
    def _exposure(dai, node, ae_max_us, anti_banding):
""", """    @staticmethod
    def _stereo_quality(dai, st, oak):
        \"\"\"depth for door/sign geometry: dense + accurate preset, speckle/spatial filtering and a range cut (the stereo
        error grows with z^2; past ~8 m the OAK-D Pro W depth is mostly noise)\"\"\"
        preset = str(oak.get("stereo_preset", "ROBOTICS")).upper()
        try:
            if preset != "NONE":
                st.setDefaultProfilePreset(getattr(dai.node.StereoDepth.PresetMode, preset))
        except Exception as e:  # noqa: BLE001
            log.warning("stereo preset %s not applied: %r" % (preset, e))
        try:
            pp = st.initialConfig.postProcessing
            pp.speckleFilter.enable = True
            pp.speckleFilter.speckleRange = 50
            pp.spatialFilter.enable = True
            pp.spatialFilter.holeFillingRadius = 2
            pp.spatialFilter.numIterations = 1
            pp.thresholdFilter.minRange = 200
            pp.thresholdFilter.maxRange = int(float(oak.get("depth_max_m", 8.0)) * 1000)
            log.info("stereo: preset %s, range %d-%d mm, speckle %s, spatial %s" % (
                preset, st.initialConfig.postProcessing.thresholdFilter.minRange, st.initialConfig.postProcessing.thresholdFilter.maxRange,
                st.initialConfig.postProcessing.speckleFilter.enable, st.initialConfig.postProcessing.spatialFilter.enable))
        except Exception as e:  # noqa: BLE001
            log.warning("stereo post-processing not applied: %r" % e)

    def _deliver_depth(self, cam, cap, wait=0.15):
        \"\"\"hand the perception node the depth frame closest in time to this colour frame (waits briefly for a late one)\"\"\"
        ls = self.listeners.get((cam, "depth"))
        if not ls:
            return
        t_end, best = time.time() + wait, None
        while True:
            with self.buf_lock:
                b = list(self.depth_buf.get(cam, ()))
            best = min(b, key=lambda e: abs(e[0] - cap)) if b else None
            if (best is not None and abs(best[0] - cap) <= 0.05) or time.time() > t_end or self.stop.is_set():
                break
            time.sleep(0.01)
        if best is None or abs(best[0] - cap) > 0.25:
            return      # nothing close in time: the node keeps the previous depth
        self.pair_dt.setdefault(cam, []).append(abs(best[0] - cap))
        del self.pair_dt[cam][:-200]
        if self._last_depth.get(cam) is not best[1]:
            self._last_depth[cam] = best[1]
            for dlv in ls:
                dlv(best[1])

    @staticmethod
    def _exposure(dai, node, ae_max_us, anti_banding):
"""),
    ("""                m.header.frame_id = cam
                if self.stamp_host:
                    m.header.stamp = rl.Stamp.from_seconds(time.time())
                for dlv in ls:
                    dlv(m)
                self.stats[cam][kind] += 1
""", """                m.header.frame_id = cam
                cap = f.getTimestamp().total_seconds() + self.mono2wall   # capture time on this PC's clock
                if self.stamp:
                    m.header.stamp = rl.Stamp.from_seconds(cap)
                if kind == "depth":   # held back, handed over with the colour frame it belongs to
                    with self.buf_lock:
                        b = self.depth_buf.setdefault(cam, [])
                        b.append((cap, m))
                        del b[:-6]
                    self.stats[cam][kind] += 1
                    continue
                self._deliver_depth(cam, cap)
                for dlv in ls:
                    dlv(m)
                self.stats[cam][kind] += 1
"""),
]

# v2 (2026-10-23 evening): the exposure loop's variable shadowed the `mono` size (TypeError in requestOutput); the stereo
# runs at stereo_fps (10) so a depth frame is always within half a period (50 ms) of the 5 fps colour frame
E["rf:ai_pc/oak_local.py"] += [
    ("""        for mono in (left, right):
            OakLocal._exposure(dai, mono, oak.get("mono_ae_max_us"), oak.get("anti_banding"))
""", """        for mono_cam in (left, right):
            OakLocal._exposure(dai, mono_cam, oak.get("mono_ae_max_us"), oak.get("anti_banding"))
"""),
    ("""        lo = left.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
        ro = right.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
""", """        sfps = float(oak.get("stereo_fps", fps))
        lo = left.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, sfps)
        ro = right.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, sfps)
"""),
]

# ---------------------------------------------------------------- rig_real.yaml
E["rf:ai_pc/rig_real.yaml"] = [
    ("""oak: {ir_dot: 0.0, mjpeg_quality: 90, color_ae_max_us: 1000, mono_ae_max_us: 1000}
""", """stereo: {width: 1280, height: 800}           # mono input of the on-camera stereo (OV9282 native); depth output stays `depth`
oak: {ir_dot: 0.6, mjpeg_quality: 90, color_ae_max_us: 8000, mono_ae_max_us: 8000, stereo_preset: ROBOTICS, depth_max_m: 8.0}
# 2026-10-23: 1 ms made corridor images dark/noisy (ISO ~1200) and signs unreadable; 8 ms blurs ~1-2 px at 0.5 m/s or
# 0.5 rad/s.  ir_dot: the OAK-D Pro W dot projector (0..1) gives the stereo texture on plain walls and doors.
""", "stereo: {width: 1280, height: 800}"),
    ("""oak: {ir_dot: 0.6, mjpeg_quality: 90, color_ae_max_us: 8000, mono_ae_max_us: 8000, stereo_preset: ROBOTICS, depth_max_m: 8.0}
""", """oak: {ir_dot: 0.6, mjpeg_quality: 90, color_ae_max_us: 8000, mono_ae_max_us: 8000, stereo_preset: ROBOTICS, depth_max_m: 8.0,
      stereo_fps: 10}                        # depth at 10 Hz: always within 50 ms of a 5 fps colour frame
"""),
]

# ---------------------------------------------------------------- ai_main.py
E["rf:ai_pc/ai_main.py"] = [
    ("""import bisect
""", """import bisect
import collections
"""),
    ("""        self.frame_id = None
        m, off = rig["mount_xyz"], rig["sensor_offset"]
""", """        self.frame_id = None
        self.off_hist = collections.deque()   # (arrival time, arrival - stamp): robot clock -> this PC's clock
        self.offset, self.t_off_log = None, 0.0
        m, off = rig["mount_xyz"], rig["sensor_offset"]
"""),
    ("""    def on_odom(self, stamp, frame_id, pq):
        with self.lock:
            self.frame_id = frame_id
            if self.hist_t and stamp <= self.hist_t[-1]:
                return
            self.hist_t.append(stamp)
            self.hist.append(np.asarray(pq, dtype=float))
            if len(self.hist) > 400:
                del self.hist_t[:100], self.hist[:100]
""", """    def on_odom(self, stamp, frame_id, pq):
        now = time.time()
        with self.lock:
            self.frame_id = frame_id
            # the PCs' clocks are not synchronised: the smallest (arrival - stamp) over the last 20 s is the clock offset plus
            # the fastest delivery; image capture times (this PC's clock) are mapped onto odometry stamps with it
            if not self.off_hist or now - self.off_hist[-1][0] > 0.05:
                self.off_hist.append((now, now - stamp))
                while now - self.off_hist[0][0] > 20.0:
                    self.off_hist.popleft()
                self.offset = min(d for _, d in self.off_hist)
                if now - self.t_off_log > 30.0:
                    self.t_off_log = now
                    logging.info("odometry clock: robot -> AI PC offset %.3f s" % self.offset)
            if self.hist_t and stamp <= self.hist_t[-1]:
                return
            self.hist_t.append(stamp)
            self.hist.append(np.asarray(pq, dtype=float))
            if len(self.hist) > 3000:
                del self.hist_t[:500], self.hist[:500]
"""),
    ("""        bp = self.base_pose(stamp)
""", """        if stamp is not None and self.offset is not None:
            stamp = stamp - self.offset       # this PC's clock -> robot clock
        bp = self.base_pose(stamp)
"""),
    ("""                            "gdino_hz": float(os.environ.get("GDINO_HZ", "1.0"))},
""", """                            "gdino_hz": float(os.environ.get("GDINO_HZ", "1.0")),
                            # the real cameras are 1280 px wide: a 40 cm strip sign is ~90 px at 2.5 m
                            "sign_min_px": float(os.environ.get("SIGN_MIN_PX", "70")),
                            "door_min_valid": float(os.environ.get("DOOR_MIN_VALID", "0.5"))},
"""),
]

# ---------------------------------------------------------------- ReasonNav room_perception.py
E["mm:nodes/room_perception.py"] = [
    ("""d("sign_min_px", 110); d("sign_max_angle_deg", 135.0)
""", """d("sign_min_px", 110); d("sign_max_angle_deg", 135.0)
        d("door_min_valid", 0.0)   # min fraction of the door box with valid depth (0 = off; glass has almost none)
"""),
    (""""sign_range", "sign_min_px", "sign_max_angle_deg")}""", """"sign_range", "sign_min_px", "sign_max_angle_deg", "door_min_valid")}"""),
    ("""            z = rig.depth_at_color(depth, x1 + 0.3 * bw, y1 + 0.35 * bh, x2 - 0.3 * bw, y2 - 0.1 * bh)
            if z.size < 20:
                continue
""", """            z = rig.depth_at_color(depth, x1 + 0.3 * bw, y1 + 0.35 * bh, x2 - 0.3 * bw, y2 - 0.1 * bh)
            if z.size < 20:
                continue
            if self.P["door_min_valid"] > 0:   # glass doors / windows: the stereo depth inside the box is mostly missing
                cells = ((min(rig.DEPTH_W, int((x2 - 0.3 * bw) / rig.DEPTH_SCALE + 1)) - int(max(0, (x1 + 0.3 * bw) / rig.DEPTH_SCALE)))
                         * (min(rig.DEPTH_H, int((y2 - 0.1 * bh) / rig.DEPTH_SCALE + 1)) - int(max(0, (y1 + 0.35 * bh) / rig.DEPTH_SCALE))))
                if z.size < self.P["door_min_valid"] * max(cells, 1):
                    continue
"""),
    ("""        if is_sign and not (0.45 <= wm <= 2.4 and 0.35 <= hm <= 2.4 and 0.55 <= hm / max(wm, 1e-3) <= 1.8):
""", """        panel = 0.45 <= wm <= 2.4 and 0.35 <= hm <= 2.4 and 0.55 <= hm / max(wm, 1e-3) <= 1.8
        strip = 0.25 <= wm <= 2.4 and 0.05 <= hm <= 0.6 and hm / max(wm, 1e-3) < 0.55   # e.g. a 40x10 cm "<- T131~T150" sign
        if is_plate and strip and wm >= 0.3:   # too long for a door plate: a range / arrow strip, parse it as a sign
            is_sign, is_plate = True, False
        if is_sign and not (panel or strip):
"""),
    ("""            nw = sum(1 for w, c in zip(d["text"], d["conf"]) if float(c) >= 60 and sum(ch.isalpha() for ch in w) >= 3)
""", """            nw = sum(1 for w, c in zip(d["text"], d["conf"]) if float(c) >= 60 and sum(ch.isalpha() for ch in w) >= 3)
            # arrow / range strips ("<- T131~T150") have no long words: a room-number-like token is enough
            num = any(float(c) >= 40 and re.search(r"\\d{2,}", w) for w, c in zip(d["text"], d["conf"]))
"""),
    ("""                if nw >= self.P["sign_ocr_words"]:
""", """                if nw >= self.P["sign_ocr_words"] or num:
"""),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rf", default=os.path.expanduser("~/raisin_ws/scripts/room_finder_net"))
    ap.add_argument("--mmdev", default=os.path.expanduser("~/ReasonNav/src/mm_dev"))
    ap.add_argument("--only", choices=("rf", "mm"), help="patch only the room_finder_net files or only ReasonNav")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    roots = {"rf": a.rf, "mm": a.mmdev}
    new, bad = {}, []
    for key, edits in E.items():
        root, rel = key.split(":", 1)
        if a.only and root != a.only:
            continue
        path = os.path.join(roots[root], rel)
        if not os.path.exists(path):
            bad.append("%s: missing file" % path)
            continue
        s = open(path).read()
        for i, ed in enumerate(edits):
            old, rep = ed[0], ed[1]
            n = s.count(old)
            if rep in s or (len(ed) > 2 and ed[2] in s):
                print("already applied: %s edit %d" % (rel, i + 1))
            elif n == 1:
                s = s.replace(old, rep)
            else:
                bad.append("%s edit %d: anchor found %d times: %r" % (rel, i + 1, n, old.strip().splitlines()[0][:90]))
        new[path] = s
    if bad:
        print("NOT APPLIED (nothing written):\n  " + "\n  ".join(bad))
        sys.exit(1)
    if a.dry_run:
        print("dry run ok:", ", ".join(new))
        return
    bk = os.path.expanduser("~/room_finder_backup/%s" % time.strftime("%Y%m%d_%H%M%S"))
    for path, s in new.items():
        dst = os.path.join(bk, path.lstrip("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(path, dst)
        open(path, "w").write(s)
        print("patched", path)
    print("backup:", bk)


if __name__ == "__main__":
    main()
