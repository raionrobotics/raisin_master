"""Simulation only: real-robot failure modes injected into the AI PC process (ai_main --cameras net, the sim).

Calibrated on the 2026-11-04 real runs (sim: 24 % of plate reads give a number, real: 12 %; VLM belief answers that flip
between wings on the same input) and the OAK-D Pro W stereo spec. Everything is off unless SIM_NOISE=1.

  SIM_PLATE_KEEP=1        a plate read that returned a number keeps it with this probability (else "no number")
  SIM_PLATE_WRONG=0       a kept number gets one digit changed / the prefix misread with this probability
  SIM_DEPTH_K=0.004       per-frame depth error: z' = z + k z^2 e, e ~ N(0, 1) shared by the frame
  SIM_DEPTH_PIX=0.006     per-pixel depth error: + pix z^2 n, n ~ N(0, 1) per pixel. Together sigma ~0.0072 z^2, median
                          absolute error 1.6 % at 3.5 m and 3.2 % at 6.5 m (OAK-D Pro W spec: < 2 % below 3.5 m, < 4 % to 6.5 m)
  SIM_MIRROR_P=0          a belief answer is mirrored to the other side (x -> 2 * mx - x, east <-> west)
  SIM_MIRROR_X=robot      mx: the robot's x at the query ("the target is the other way"), or a fixed map x
  SIM_VLM_OUTAGE=a-b,...  VLM calls fail during these windows (s after start), like the AI PC's LTE dropping (default none)
  SIM_NOISE_SEED=0        0 = a fresh seed per run
Real hardware rates (0 = as fast as the sim gives them; the measured rates are logged every 60 s either way):
  SIM_CAM_HZ=0            colour frames per camera are dropped down to this rate (12 MP over the PoE switch)
  SIM_YOLO_MS=0           one YOLO door pass takes at least this long (Jetson TensorRT)
  SIM_GDINO_MS=0          one GDINO /detect call takes at least this long (Jetson TensorRT, 2 in flight)
  SIM_VLM_EXTRA_MS=0      added to every OpenAI call (LTE round trip)
"""
import logging
import os
import random
import re
import time

import numpy as np

LOG = logging.getLogger("sim_noise")


def _f(name, default):
    return float(os.environ.get(name, default))


ON = os.environ.get("SIM_NOISE", "0") == "1"
_seed = int(_f("SIM_NOISE_SEED", 0)) or int(time.time() * 1000) % 2 ** 31
RNG = random.Random(_seed)
NP = np.random.default_rng(_seed)
T0 = time.time()
STATS = {"plate_dropped": 0, "plate_wrong": 0, "mirrored": 0, "vlm_outage": 0}
RATE = {"rgb": {}, "yolo": [0, 0.0], "gdino": [0, 0.0], "ocr": [0, 0.0], "vlm": [0, 0.0]}   # rgb per camera; [count, total s]


def wrap_depth_routes(router, cams):
    """perturb the depth images the perception node receives (the lidar map stays exact, as on the robot)"""
    k, pix = _f("SIM_DEPTH_K", 0.004), _f("SIM_DEPTH_PIX", 0.006)
    for cam in cams:
        topic = "/%s/depth" % cam
        route = router.sub_routes.get(topic)
        if route is None:
            continue

        def noisy(deliver, route=route):
            def d(m):
                z = np.frombuffer(bytes(m.data), np.float32).reshape(m.height, m.width)
                e = NP.normal()
                z2 = z + z * z * (k * e + pix * NP.normal(size=z.shape).astype(np.float32))
                z2 = np.where(np.isfinite(z) & (z > 0), np.maximum(z2, 0.05), z).astype(np.float32)
                m.data = z2.tobytes()
                deliver(m)
            route(d)
        router.sub_routes[topic] = noisy


def wrap_rgb_routes(router, cams):
    """drop colour frames down to SIM_CAM_HZ per camera and count what gets through"""
    hz = _f("SIM_CAM_HZ", 0)
    for cam in cams:
        topic = "/%s/rgb" % cam
        route = router.sub_routes.get(topic)
        if route is None:
            continue
        RATE["rgb"][cam] = 0

        def throttled(deliver, route=route, cam=cam):
            nxt = [0.0]

            def d(m):
                now = time.time()
                if hz > 0:     # average rate hz, also when the sim's rate is not a multiple of it
                    if now < nxt[0]:
                        return
                    nxt[0] = max(nxt[0] + 1.0 / hz, now - 0.5 / hz)
                RATE["rgb"][cam] += 1
                deliver(m)
            route(d)
        router.sub_routes[topic] = throttled


def _padded(fn, key, min_s, extra_s=0.0):
    def w(*a, **kw):
        t0 = time.time()
        try:
            return fn(*a, **kw)
        finally:
            dt = time.time() - t0
            pad = max(min_s - dt, 0.0) + extra_s
            if pad > 0:
                time.sleep(pad)
            RATE[key][0] += 1
            RATE[key][1] += dt + pad
    return w


def patch_perception(perc_mod):
    """YOLO and GDINO at the Jetson's speed: each call is padded to SIM_YOLO_MS / SIM_GDINO_MS"""
    yolo_s, gdino_s = _f("SIM_YOLO_MS", 0) / 1000.0, _f("SIM_GDINO_MS", 0) / 1000.0
    P = perc_mod.RoomPerception
    init = P.__init__

    def init_w(self, *a, **kw):
        init(self, *a, **kw)
        self.yolo.predict = _padded(self.yolo.predict, "yolo", yolo_s)
    P.__init__ = init_w

    class _Req:   # room_perception's `requests`: only its /detect posts go to GDINO
        def __getattr__(self, k):
            return getattr(_requests, k)
    import requests as _requests
    shim = _Req()
    shim.post = _padded(_requests.post, "gdino", gdino_s)
    ocr_s = _f("SIM_OCR_MS", 0) / 1000.0   # the OCR loop posts through its own requests.Session (Orin: ~350 ms per 12 MP frame)

    def session():
        s = _requests.Session()
        s.post = _padded(s.post, "ocr", ocr_s)
        return s
    shim.Session = session
    perc_mod.requests = shim


def patch_vlm_latency(vlm_mod):
    V = vlm_mod.VLM
    V._complete = _padded(V._complete, "vlm", 0.0, _f("SIM_VLM_EXTRA_MS", 0) / 1000.0)


def rates():
    el = max(time.time() - T0, 1e-3)
    cams = " ".join("%s %.2f" % (c.replace("oak_", ""), n / el) for c, n in RATE["rgb"].items())
    def per(k):
        n, tot = RATE[k]
        return "%.2f/s, %.0f ms" % (n / el, 1000.0 * tot / n if n else 0.0)
    return "rates over %.0f s: rgb Hz [%s]; yolo %s; gdino %s; ocr %s; vlm %s" % (el, cams, per("yolo"), per("gdino"), per("ocr"), per("vlm"))


def _misread(num):
    s = list(num)
    digits = [i for i, c in enumerate(s) if c.isdigit()]
    if s and not s[0].isdigit() and RNG.random() < 0.3:     # "T135" -> "7135" / "1135"
        s[0] = RNG.choice("71")
    elif digits:
        i = RNG.choice(digits)
        s[i] = RNG.choice([c for c in "0123456789" if c != s[i]])
    return "".join(s)


def patch_vlm(vlm_mod):
    keep, wrong = _f("SIM_PLATE_KEEP", 1.0), _f("SIM_PLATE_WRONG", 0.0)
    windows = []
    for w in filter(None, os.environ.get("SIM_VLM_OUTAGE", "").split(",")):
        a, b = w.split("-")
        windows.append((float(a), float(b)))
    V = vlm_mod.VLM
    read_plate, complete = V.read_plate, V._complete

    def read_plate_noisy(self, crop):
        num, conf, raw = read_plate(self, crop)
        if num:
            if RNG.random() > keep:
                STATS["plate_dropped"] += 1
                return None, conf, raw + " [sim: dropped]"
            if RNG.random() < wrong:
                STATS["plate_wrong"] += 1
                num = _misread(num)
                raw += " [sim: misread]"
        return num, conf, raw

    def complete_outage(self, content, max_tokens):
        t = time.time() - T0
        if any(a <= t <= b for a, b in windows):
            STATS["vlm_outage"] += 1
            raise ConnectionError("sim: VLM outage")
        return complete(self, content, max_tokens)
    V.read_plate = read_plate_noisy
    V._complete = complete_outage


def _swap_ew(s):
    return re.sub(r"east|west|East|West|EAST|WEST",
                  lambda m: {"east": "west", "west": "east", "East": "West", "West": "East", "EAST": "WEST", "WEST": "EAST"}[m.group(0)], s)


def patch_finder(finder_mod):
    p, mx_env = _f("SIM_MIRROR_P", 0.0), os.environ.get("SIM_MIRROR_X", "robot")
    F = finder_mod.RoomFinder
    query = F._belief_query

    def query_mirrored(self, *a, **kw):
        info = query(self, *a, **kw)
        if not isinstance(info, dict) or RNG.random() >= p:
            return info
        STATS["mirrored"] += 1
        rp = kw.get("rp", a[1] if len(a) > 1 else None)
        mx = float(rp[0]) if mx_env == "robot" and rp is not None else float(mx_env if mx_env != "robot" else 0.0)
        out = dict(info)
        for k in ("goal_xy", "via_xy"):
            if out.get(k) is not None:
                out[k] = (2 * mx - out[k][0], out[k][1])
        for k, v in list(out.items()):
            if isinstance(v, str):
                out[k] = _swap_ew(v)
            elif isinstance(v, list):
                out[k] = [_swap_ew(x) if isinstance(x, str) else x for x in v]
        out["patterns"] = "[sim: mirrored] " + str(out.get("patterns", ""))
        return out
    F._belief_query = query_mirrored


def summary():
    return "sim noise (seed %d): %s; %s" % (_seed, ", ".join("%s %d" % kv for kv in STATS.items()), rates())
