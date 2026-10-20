"""OAK-D Pro W cameras attached to the AI PC (PoE, depthai v3) -> the same image messages the network path delivers.

rig.yaml:  cameras: {oak_front: {yaw: 0.0, ip: 192.168.1.103}, ...}   (a camera without `ip` is not opened)
           color: {width, height, fps}   depth: {width, height}   (4:3 both: depth is aligned to the colour sensor)
           oak: {ir_dot: 0.0..1.0, mjpeg_quality: 90}
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
        self.listeners = {}     # (cam, kind) -> [deliver]
        self.devices, self.stop = {}, threading.Event()
        self.stats = {}

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
        oak = self.rig.get("oak", {})
        hfovs = []
        for cam, c in self.rig["cameras"].items():
            ip = c.get("ip")
            if not ip:
                log.warning("%s has no ip in the rig: not opened" % cam)
                continue
            dev = self._connect(ip, tries)
            pipe, qc, qd = self._build(dai, dev, cw, ch, fps, dw, dh, oak)
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
    def _build(dai, dev, cw, ch, fps, dw, dh, oak):
        pipe = dai.Pipeline(dev)
        color = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_A)
        cout = color.requestOutput((cw, ch), dai.ImgFrame.Type.NV12, dai.ImgResizeMode.CROP, fps)
        enc = pipe.create(dai.node.VideoEncoder)
        enc.setDefaultProfilePreset(fps, dai.VideoEncoderProperties.Profile.MJPEG)
        enc.setQuality(int(oak.get("mjpeg_quality", 90)))
        cout.link(enc.input)
        left = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_B)
        right = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_C)
        lo = left.requestOutput((640, 400), dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
        ro = right.requestOutput((640, 400), dai.ImgFrame.Type.GRAY8, dai.ImgResizeMode.CROP, fps)
        st = pipe.create(dai.node.StereoDepth)
        st.build(lo, ro)
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
                    data, enc = np.ascontiguousarray(img), "bgr8"
                else:
                    d = f.getFrame().astype(np.float32) * 0.001             # mm -> m, 0 = no depth
                    data, enc = np.ascontiguousarray(d), "32FC1"
                m = rl.Image()
                m.height, m.width, m.encoding = data.shape[0], data.shape[1], enc
                m.step, m.data = data.strides[0], data.tobytes()
                m.header.frame_id = cam
                if self.stamp_host:
                    m.header.stamp = rl.Stamp.from_seconds(time.time())
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
