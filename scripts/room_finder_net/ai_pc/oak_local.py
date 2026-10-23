"""OAK-D Pro W cameras attached to the AI PC (PoE, depthai v3) -> the same image messages the network path delivers.

rig.yaml:  cameras: {oak_front: {yaw: 0.0, ip: 192.168.1.103}, ...}   (a camera without `ip` is not opened)
           color: {width, height, fps}   depth: {width, height}   (4:3 both: depth is aligned to the colour sensor)
           oak: {ir_dot: 0.0..1.0, mjpeg_quality: 90, color_ae_max_us, mono_ae_max_us, anti_banding: off|50|60|auto}
The colour stream is JPEG-encoded on the camera (a gigabit link cannot carry three raw 12 MP streams) and decoded here.
Depth is the on-camera StereoDepth aligned to CAM_A, converted to float32 metres (what room_perception expects).
Frames carry stamp 0 unless `stamp_host` is set: the robot's odometry runs on the robot PC's clock, and with stamp 0 the
perception node uses the latest pose instead of looking one up at the camera time."""
import logging
import math
import threading
import time

import numpy as np

log = logging.getLogger("oak_local")


class OakLocal:
    def __init__(self, rig, rosless, stamp_host=False):
        self.rig, self.rl, self.stamp_host = rig, rosless, stamp_host
        self.stamp = bool(rig.get("oak", {}).get("stamp", True)) or stamp_host   # frames carry their capture time
        self.listeners = {}     # (cam, kind) -> [deliver]
        self.devices, self.stop = {}, threading.Event()
        self.stats, self.expo = {}, {}
        self.depth_buf, self.buf_lock, self._last_depth, self.pair_dt = {}, threading.Lock(), {}, {}
        self.mono2wall = time.time() - time.monotonic()   # depthai timestamps are steady_clock (= time.monotonic)

    # ---- router hooks: the nodes subscribe to "/<cam>/rgb" and "/<cam>/depth"
    def route(self, cam, kind):
        def attach(deliver):
            self.listeners.setdefault((cam, kind), []).append(deliver)
        return attach

    def open(self, tries=12):
        """connect every camera with an ip, build its pipeline, start the reader threads; fills rig['hfov'] / sizes from the device"""
        import depthai as dai
        self.dai = dai
        cc, dc = self.rig["color"], self.rig["depth"]
        cw, ch, fps = int(cc["width"]), int(cc["height"]), float(cc.get("fps", 5))
        dw, dh = int(dc["width"]), int(dc["height"])
        sc = self.rig.get("stereo", {})
        mono = (int(sc.get("width", 640)), int(sc.get("height", 400)))
        oak = self.rig.get("oak", {})
        hfovs = []
        for cam, c in self.rig["cameras"].items():
            ip = c.get("ip")
            if not ip:
                log.warning("%s has no ip in the rig: not opened" % cam)
                continue
            dev = self._connect(ip, tries)
            pipe, qc, qd = self._build(dai, dev, cw, ch, fps, dw, dh, oak, mono)
            k = dev.readCalibration().getCameraIntrinsics(dai.CameraBoardSocket.CAM_A, cw, ch)
            hfovs.append(2.0 * math.atan(cw / (2.0 * k[0][0])))
            self.devices[cam] = (dev, pipe)
            self.stats[cam] = {"rgb": 0, "depth": 0}
            pipe.start()
            for kind, q in (("rgb", qc), ("depth", qd)):
                threading.Thread(target=self._reader, args=(cam, kind, q), daemon=True).start()
            log.info("%s: %s up (%dx%d colour @%.0f fps, depth %dx%d, hfov %.1f deg)" % (cam, ip, cw, ch, fps, dw, dh, math.degrees(hfovs[-1])))
        if not self.devices:
            raise SystemExit("no camera opened")
        h = float(np.mean(hfovs))
        if max(hfovs) - min(hfovs) > 0.03:
            log.warning("the cameras report different horizontal fields of view (%s): using the mean" % [round(x, 3) for x in hfovs])
        self.rig["hfov"] = h
        return h

    def _connect(self, ip, tries):
        for i in range(tries):
            try:
                return self.dai.Device(self.dai.DeviceInfo(ip))
            except RuntimeError as e:
                log.warning("camera %s: attempt %d: %s" % (ip, i + 1, str(e)[:80]))
                time.sleep(3)
        raise SystemExit("camera %s not reachable" % ip)

    @staticmethod
    def _build(dai, dev, cw, ch, fps, dw, dh, oak, mono=(640, 400)):
        pipe = dai.Pipeline(dev)
        color = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_A)
        OakLocal._exposure(dai, color, oak.get("color_ae_max_us"), oak.get("anti_banding"))
        cout = color.requestOutput((cw, ch), dai.ImgFrame.Type.NV12, dai.ImgResizeMode.CROP, fps)
        enc = pipe.create(dai.node.VideoEncoder)
        enc.setDefaultProfilePreset(fps, dai.VideoEncoderProperties.Profile.MJPEG)
        enc.setQuality(int(oak.get("mjpeg_quality", 90)))
        cout.link(enc.input)
        left = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_B)
        right = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_C)
        for mono_cam in (left, right):
            OakLocal._exposure(dai, mono_cam, oak.get("mono_ae_max_us"), oak.get("anti_banding"))
        sfps = float(oak.get("stereo_fps", fps))
        lo = left.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, sfps)
        ro = right.requestOutput(mono, dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, sfps)
        st = pipe.create(dai.node.StereoDepth)
        st.build(lo, ro)
        OakLocal._stereo_quality(dai, st, oak)
        st.setDepthAlign(dai.CameraBoardSocket.CAM_A)
        st.setLeftRightCheck(True)
        st.setSubpixel(True)
        st.setOutputSize(dw, dh)
        # the wide lenses: undistort through the mesh, not a homography
        st.useHomographyRectification(False)
        st.enableDistortionCorrection(True)
        ir = float(oak.get("ir_dot", 0.0))
        if ir > 0:
            dev.setIrLaserDotProjectorIntensity(ir)
        return pipe, enc.bitstream.createOutputQueue(maxSize=2, blocking=False), st.depth.createOutputQueue(maxSize=2, blocking=False)

    @staticmethod
    def _stereo_quality(dai, st, oak):
        """depth for door/sign geometry: dense + accurate preset, speckle/spatial filtering and a range cut (the stereo
        error grows with z^2; past ~8 m the OAK-D Pro W depth is mostly noise)"""
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
        """hand the perception node the depth frame closest in time to this colour frame (waits briefly for a late one)"""
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
        """auto exposure stays on; a cap on the exposure time makes it raise the gain (ISO) instead -> less motion blur"""
        ctl = node.initialControl
        if ae_max_us:
            ctl.setAutoExposureLimit(int(ae_max_us))
        if anti_banding is not None:   # off | 50 | 60 | auto (mains flicker; 60 Hz in Korea)
            m = dai.CameraControl.AntiBandingMode
            ctl.setAntiBandingMode({"off": m.OFF, "50": m.MAINS_50_HZ, "60": m.MAINS_60_HZ, "auto": m.AUTO}[str(anti_banding).lower()])

    def _log_exposure(self, cam, f, img):
        """every 5 s per camera: median exposure (ms), ISO and mean grey level of the colour frames"""
        s = self.expo.setdefault(cam, {"t": time.time(), "e": [], "iso": [], "lum": []})
        try:
            s["e"].append(f.getExposureTime().total_seconds() * 1e3)
            s["iso"].append(f.getSensitivity())
        except Exception:  # noqa: BLE001
            pass
        s["lum"].append(float(img[::8, ::8].mean()))
        if time.time() - s["t"] >= 5.0:
            med = lambda v: float(np.median(v)) if v else float("nan")
            log.info("%s exposure %.2f ms  ISO %.0f  mean grey %.0f/255" % (cam, med(s["e"]), med(s["iso"]), med(s["lum"])))
            self.expo[cam] = {"t": time.time(), "e": [], "iso": [], "lum": []}

    def _reader(self, cam, kind, q):
        import cv2
        rl = self.rl
        while not self.stop.is_set():
            f = q.tryGet()
            if f is None:
                time.sleep(0.005)
                continue
            ls = self.listeners.get((cam, kind))
            if not ls:
                continue
            try:
                if kind == "rgb":
                    img = cv2.imdecode(f.getData(), cv2.IMREAD_COLOR)        # BGR, like the simulated stream
                    if img is None:
                        continue
                    self._log_exposure(cam, f, img)
                    data, enc = np.ascontiguousarray(img), "bgr8"
                else:
                    d = f.getFrame().astype(np.float32) * 0.001             # mm -> m, 0 = no depth
                    data, enc = np.ascontiguousarray(d), "32FC1"
                m = rl.Image()
                m.height, m.width, m.encoding = data.shape[0], data.shape[1], enc
                m.step, m.data = data.strides[0], data.tobytes()
                m.header.frame_id = cam
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
            except Exception as e:  # noqa: BLE001
                log.warning("%s %s frame dropped: %r" % (cam, kind, e))

    def close(self):
        self.stop.set()
        for dev, pipe in self.devices.values():
            try:
                pipe.stop()
                dev.close()
            except Exception:  # noqa: BLE001
                pass
