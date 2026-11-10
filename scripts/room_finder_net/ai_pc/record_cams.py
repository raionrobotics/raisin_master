#!/usr/bin/env python3
"""Record the head cameras' colour frames for offline work (OCR / detector tests, videos) while the robot is driven by hand.

    ~/room_finder_venv/bin/python ai_pc/record_cams.py [--hz 1] [--rig ai_pc/rig_real.yaml] [--out DIR]

Opens every camera with an `ip` in the rig (same resolution and exposure caps as oak_local, colour only, no depth) and writes the
camera's own MJPEG frames unchanged to <out>/<cam>/<cam>_<unix ms>.jpg at most --hz per camera, plus <out>/frames.csv
(time, camera, file, exposure ms, ISO). Default <out>: <workspace>/log/cam_record/<time>. Stop with Ctrl+C.
The cameras can be open in one program only: stop ai_main first. 12 MP at 1 Hz is ~7 MB/s for three cameras."""
import argparse
import logging
import os
import sys
import threading
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oak_local  # noqa: E402

log = logging.getLogger("record_cams")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rig", default=os.path.join(HERE, "rig_real.yaml"))
    ap.add_argument("--hz", type=float, default=1.0, help="frames saved per camera per second (the camera runs at the rig fps)")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    import depthai as dai

    rig = yaml.safe_load(open(a.rig))
    ws = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
    out = a.out or os.path.join(ws, "log", "cam_record", time.strftime("%Y%m%d_%H%M%S"))
    cc, oak = rig["color"], rig.get("oak", {})
    cw, ch, fps = int(cc["width"]), int(cc["height"]), float(cc.get("fps", 5))
    stop, lock = threading.Event(), threading.Lock()
    os.makedirs(out, exist_ok=True)
    csv = open(os.path.join(out, "frames.csv"), "a")
    csv.write("time,camera,file,exposure_ms,iso\n")
    stats, running = {}, []

    def reader(cam, q):
        last, period = 0.0, 1.0 / max(a.hz, 1e-3)
        os.makedirs(os.path.join(out, cam), exist_ok=True)
        while not stop.is_set():
            f = q.tryGet()
            if f is None:
                time.sleep(0.005)
                continue
            now = time.time()
            if now - last < period:
                continue
            last = now
            name = "%s_%d.jpg" % (cam, int(now * 1000))
            data = f.getData()
            with open(os.path.join(out, cam, name), "wb") as fh:
                fh.write(data.tobytes() if hasattr(data, "tobytes") else bytes(data))
            try:
                exp, iso = f.getExposureTime().total_seconds() * 1e3, f.getSensitivity()
            except Exception:  # noqa: BLE001
                exp, iso = float("nan"), -1
            with lock:
                csv.write("%.3f,%s,%s/%s,%.2f,%d\n" % (now, cam, cam, name, exp, iso))
                csv.flush()
                s = stats.setdefault(cam, [0, 0])
                s[0] += 1
                s[1] += len(data)

    for cam, c in rig["cameras"].items():
        if not c.get("ip"):
            continue
        dev = dai.Device(dai.DeviceInfo(c["ip"]))
        pipe = dai.Pipeline(dev)
        color = pipe.create(dai.node.Camera).build(dai.CameraBoardSocket.CAM_A)
        oak_local.OakLocal._exposure(dai, color, oak.get("color_ae_max_us"), oak.get("anti_banding"))
        enc = pipe.create(dai.node.VideoEncoder)
        enc.setDefaultProfilePreset(fps, dai.VideoEncoderProperties.Profile.MJPEG)
        enc.setQuality(int(oak.get("mjpeg_quality", 90)))
        color.requestOutput((cw, ch), dai.ImgFrame.Type.NV12, dai.ImgResizeMode.CROP, fps).link(enc.input)
        q = enc.bitstream.createOutputQueue(maxSize=2, blocking=False)
        pipe.start()
        running.append((dev, pipe))
        threading.Thread(target=reader, args=(cam, q), daemon=True).start()
        log.info("%s (%s): %dx%d @ %.0f fps, saving %.1f per second" % (cam, c["ip"], cw, ch, fps, a.hz))
    log.info("recording to %s -- Ctrl+C to stop" % out)
    t0 = time.time()
    try:
        while True:
            time.sleep(10.0)
            with lock:
                log.info("%.0f s: %s" % (time.time() - t0, ", ".join("%s %d frames %.0f MB" % (k, v[0], v[1] / 1e6) for k, v in sorted(stats.items()))))
    except KeyboardInterrupt:
        pass
    stop.set()
    for dev, pipe in running:
        try:
            pipe.stop()
            dev.close()
        except Exception:  # noqa: BLE001
            pass
    log.info("saved to %s" % out)


if __name__ == "__main__":
    main()
