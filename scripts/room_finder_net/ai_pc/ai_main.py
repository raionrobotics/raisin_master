#!/usr/bin/env python3
"""AI PC process of the room finder: runs ReasonNav's room_perception + room_finder (YOLO, Grounding DINO client, VLM, belief
policy ...) with raisin_network as the only middleware -- no ROS 2 anywhere.

  robot PC  ──raisin_network──►  oak_*/rgb|depth, /Odometry/base          (read directly from the robot's raisin node)
  robot PC  ──raisin_network──►  room_finder/map (occupancy grid built on the robot), service room_finder/goal
  this process: perception + finder in one process, the goal is sent as a service call to the robot gateway.

  ai_main.py --target 3018 --robot-id <robot nickname> --gateway-id room_finder_gw [--iface eth0 ...]
"""
import argparse
import bisect
import collections
import json
import logging
import math
import os
import sys
import threading
import time

import numpy as np
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "raisin_py", "build"))   # built module; PYTHONPATH also works
import rosless  # noqa: E402


def quat_mul(a, b):
    ax, ay, az, aw = a
    bx, by, bz, bw = b
    return (aw * bx + ax * bw + ay * bz - az * by, aw * by - ax * bz + ay * bw + az * bx,
            aw * bz + ax * by - ay * bx + az * bw, aw * bw - ax * bx - ay * by - az * bz)


def quat_rot(q, v):
    x, y, z, w = q
    R = np.array([[1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)],
                  [2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)],
                  [2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)]])
    return R @ np.asarray(v, dtype=float)


def yaw_quat(yaw):
    return (0.0, 0.0, math.sin(yaw / 2), math.cos(yaw / 2))


class PoseModel:
    """map <- base_link from the robot's odometry (history kept for image-time lookups), map <- camera = base pose * static mount"""

    def __init__(self, rig):
        self.hist_t, self.hist = [], []
        self.lock = threading.Lock()
        self.frame_id = None
        self.off_hist = collections.deque()   # (arrival time, arrival - stamp): robot clock -> this PC's clock
        self.offset, self.t_off_log = None, 0.0
        m, off = rig["mount_xyz"], rig["sensor_offset"]
        self.static = {"base_link": ((0.0, 0.0, 0.0), (0.0, 0.0, 0.0, 1.0))}
        for name, c in rig["cameras"].items():
            y = float(c["yaw"])
            if "xyz" in c:   # measured position of this camera (overrides mount_xyz + sensor_offset)
                self.static[name] = (tuple(float(v) for v in c["xyz"]), yaw_quat(y))
            else:
                self.static[name] = ((m[0] + off * math.cos(y), m[1] + off * math.sin(y), m[2]), yaw_quat(y))

    def on_odom(self, stamp, frame_id, pq):
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

    def base_pose(self, stamp=None):
        with self.lock:
            if not self.hist:
                return None
            if stamp is None or stamp >= self.hist_t[-1]:
                return self.hist[-1] if (stamp is None or stamp - self.hist_t[-1] < 0.5) else None
            i = bisect.bisect_left(self.hist_t, stamp)
            if i == 0:
                return self.hist[0] if self.hist_t[0] - stamp < 0.5 else None
            t0, t1 = self.hist_t[i - 1], self.hist_t[i]
            a, b = self.hist[i - 1], self.hist[i]
            w = (stamp - t0) / max(t1 - t0, 1e-6)
            p = a[:3] * (1 - w) + b[:3] * w
            q = a[3:] * (1 - w) + (b[3:] if np.dot(a[3:], b[3:]) >= 0 else -b[3:]) * w
            return np.concatenate([p, q / np.linalg.norm(q)])

    def lookup(self, frame, stamp=None):
        if frame not in self.static:
            return None
        if stamp is not None and self.offset is not None:
            stamp = stamp - self.offset       # this PC's clock -> robot clock
        bp = self.base_pose(stamp)
        if bp is None:
            return None
        t, q = self.static[frame]
        pos = bp[:3] + quat_rot(tuple(bp[3:]), t)
        return tuple(pos), quat_mul(tuple(bp[3:]), q)


def apply_rig(rig):
    """the geometry module hard-codes the simulated OAK rig; point it at the configured one before the nodes read it"""
    from mm_dev.room_finder import camera_rig as cr
    cr.CAMERAS = tuple(rig["cameras"].keys())
    cr.COLOR_W, cr.COLOR_H = int(rig["color"]["width"]), int(rig["color"]["height"])
    cr.DEPTH_W, cr.DEPTH_H = int(rig["depth"]["width"]), int(rig["depth"]["height"])
    cr.HFOV = float(rig["hfov"])
    cr.FX = (cr.COLOR_W / 2.0) / math.tan(cr.HFOV / 2.0)
    cr.CX, cr.CY = cr.COLOR_W / 2.0, cr.COLOR_H / 2.0
    cr.DEPTH_SCALE = cr.COLOR_W / cr.DEPTH_W


def install_dummy_vlm():
    """Replace the OpenAI call in ReasonNav's VLM client (this PC has no internet).  Answers are well-formed but empty:
    plate -> number null, sign -> [], belief query -> no region, so the finder explores frontiers and never confirms a label."""
    from mm_dev.room_finder import vlm as V

    class _Client:
        def with_options(self, **kw):
            return self

    def init(self, model=None):
        self.model, self.client, self.calls = "dummy", _Client(), 0

    def complete(self, content, max_tokens):
        text = content if isinstance(content, str) else next((c["text"] for c in content if c.get("type") == "text"), "")
        if text.startswith(("The image is a crop of a hospital wall", "The image is a crop of an indoor wall")):
            return '{"number": null, "confidence": 0.0}'
        if text.startswith("The image is a crop of a navigational sign"):
            return "[]"
        return '{"region": "", "patterns": "dummy VLM", "reasoning": "dummy VLM"}'

    V.VLM.__init__, V.VLM._complete = init, complete
    logging.warning("DUMMY VLM: no OpenAI calls; room numbers cannot be read through the VLM")


def wait_servers(servers):
    """block until every (name, http url) accepts a TCP connection; '' = not used. One command for both servers is in the README."""
    import socket
    import urllib.parse
    for name, url in servers:
        if not url:
            continue
        u = urllib.parse.urlparse(url)
        n = 0
        while True:
            try:
                socket.create_connection((u.hostname, u.port or 80), 1.0).close()
                break
            except OSError:
                if n % 10 == 0:
                    logging.error("%s server not running at %s: start it (README 'Real robot runs'); waiting ..." % (name, url))
                n += 1
                time.sleep(1.0)
        if n:
            logging.info("%s server up at %s" % (name, url))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="room number to find")
    ap.add_argument("--robot-id", required=True, help="raisin network id of the robot (its robot_nickname)")
    ap.add_argument("--gateway-id", default="room_finder_gw", help="raisin network id of the robot-side gateway")
    ap.add_argument("--id", default="room_finder_ai", help="raisin network id of this process")
    ap.add_argument("--iface", nargs="*", default=["lo"], help="network interfaces for raisin discovery")
    ap.add_argument("--rig", default=os.path.join(HERE, "rig.yaml"))
    ap.add_argument("--mmdev", default=os.environ.get("MMDEV", "/home/user/tips_ws/src/ReasonNav/src/mm_dev"),
                    help="ReasonNav's mm_dev source directory")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--max-time", type=float, default=1500.0)
    ap.add_argument("--policy", default=os.environ.get("POLICY", "belief"))
    ap.add_argument("--belief-signs", default=os.environ.get("BELIEF_SIGNS", "vlm"))
    ap.add_argument("--yolo", default=os.environ.get("ROOM_FINDER_YOLO", ""), help="door YOLO weights (default: the repo copy)")
    ap.add_argument("--exit-when-done", action="store_true")
    ap.add_argument("--env-key", action="store_true", help="use OPENAI_API_KEY from the environment instead of mm_dev/config/.env")
    ap.add_argument("--cameras", choices=("net", "local"), default="net",
                    help="net: images come from the robot over raisin_network; local: OAK cameras (rig.yaml `ip`) attached to this PC")
    ap.add_argument("--stamp-host", action="store_true", help="local cameras: stamp frames with this PC's clock (needs clocks synchronised with the robot; "
                    "default stamp 0 = use the latest odometry pose)")
    ap.add_argument("--dummy-vlm", action="store_true", default=os.environ.get("ROOM_FINDER_DUMMY_VLM", "") == "1",
                    help="no OpenAI: plate reads return 'no plate', sign reads return no cues, belief queries return no region")
    ap.add_argument("--debug-port", type=int, default=8082,
                    help="MJPEG http stream of /room_finder/debug_image (camera tiles + detection boxes); 0 = off")
    ap.add_argument("--log-debug-hz", type=float, default=float(os.environ.get("LOG_DEBUG_HZ", "0")),
                    help="also save that image (what :8082 shows) to <run>/debug_image at this rate (it is made at 2 Hz); 0 = off")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    rig = yaml.safe_load(open(a.rig))

    # ---- raisin network
    import raisin_boot
    raisin_boot.preload()
    import raisin_py
    net = raisin_py.Net(a.id, a.iface)
    robot = gw = None
    while robot is None or gw is None:
        robot = robot or net.connect(a.robot_id)
        gw = gw or net.connect(a.gateway_id)
        if robot is None or gw is None:
            logging.info("waiting for %s%s" % ("robot " + a.robot_id + " " if robot is None else "", "gateway " + a.gateway_id if gw is None else ""))
            time.sleep(1.0)
    logging.info("connected to robot '%s' and gateway '%s'" % (a.robot_id, a.gateway_id))

    # ---- routing of the topics the nodes use
    router = rosless.Router()
    poses = PoseModel(rig)
    router.pose_provider = lambda frame, stamp: poses.lookup(frame, stamp)
    net.subscribe_odometry(robot, rig["topics"]["odom"], lambda t, f, pq, tw: poses.on_odom(t, f, pq))

    def image_route(cam, kind):
        topic = rig["topics"][kind].format(cam=cam)

        def attach(deliver):
            def cb(stamp, frame, h, w, enc, data):
                m = rosless.Image()
                m.header.stamp, m.header.frame_id = rosless.Stamp.from_seconds(stamp), frame
                m.height, m.width, m.encoding, m.data = h, w, enc, data
                deliver(m)
            net.subscribe_image(robot, topic, cb)
        return attach

    oak = None
    if a.cameras == "local":
        import oak_local
        oak = oak_local.OakLocal(rig, rosless, stamp_host=a.stamp_host)
        oak.open()      # also sets rig["hfov"] from the camera calibration
        for cam in rig["cameras"]:
            router.sub_routes["/%s/rgb" % cam] = oak.route(cam, "rgb")
            router.sub_routes["/%s/depth" % cam] = oak.route(cam, "depth")
    else:
        for cam in rig["cameras"]:
            router.sub_routes["/%s/rgb" % cam] = image_route(cam, "rgb")
            router.sub_routes["/%s/depth" % cam] = image_route(cam, "depth")

    def grid_route(deliver):
        def cb(stamp, frame, res, x0, y0, g):
            m = rosless.OccupancyGrid()
            m.header.frame_id = frame
            m.info.resolution, m.info.height, m.info.width = res, g.shape[0], g.shape[1]
            m.info.origin.position.x, m.info.origin.position.y = x0, y0
            m.data = g.reshape(-1)
            deliver(m)
        net.subscribe_grid(gw, "room_finder/map", cb)
    router.sub_routes["/global_costmap/costmap"] = grid_route

    # goal: latest wins, sent from a worker so the finder's tick never blocks on the network
    goal_box = {"msg": None}
    goal_cv = threading.Condition()

    def goal_send(msg, use_yaw):
        with goal_cv:
            goal_box["msg"] = (msg, use_yaw)
            goal_cv.notify()

    def goal_worker():
        while rosless.ok():
            with goal_cv:
                while goal_box["msg"] is None and rosless.ok():
                    goal_cv.wait(0.5)
                item, goal_box["msg"] = goal_box["msg"], None
            if item is None:
                continue
            m, use_yaw = item
            payload = json.dumps({"x": m.pose.position.x, "y": m.pose.position.y, "yaw": rosless.quat_to_yaw(m.pose.orientation),
                                  "use_yaw": bool(use_yaw), "t": time.time()})
            ok, msg = net.call_string(gw, "room_finder/goal", payload, 3.0)
            if not ok:
                logging.warning("goal rejected / lost: %s" % msg)
    threading.Thread(target=goal_worker, daemon=True).start()
    router.pub_routes["/room_finder/goal"] = lambda m: goal_send(m, False)
    router.pub_routes["/room_finder/goal_yaw"] = lambda m: goal_send(m, True)

    # ---- landmarks + finder state for the gateway's map viewer (latest wins, ~1 Hz; the nodes keep their local delivery)
    viz = {"registry": None, "finder": None}

    def on_registry(m):
        r = json.loads(m.data)
        viz["registry"] = {
            "doors": [{k: d.get(k) for k in ("id", "x", "y", "conf", "label", "nrm", "width")} for d in r.get("doors", [])],
            "labels": [{k: lb.get(k) for k in ("id", "x", "y", "number", "score")} for lb in r.get("labels", [])],
            "signs": [{"id": s["id"], "x": s["x"], "y": s["y"], "valid": s.get("valid"), "dead": s.get("dead"),
                       "cues": [{k: c.get(k) for k in ("place", "bearing", "bearing2", "lo", "hi", "pre")} for c in s.get("cues", [])]}
                      for s in r.get("signs", [])]}

    def on_finder(m):
        s = json.loads(m.data)
        viz["finder"] = {k: s.get(k) for k in ("state", "target", "elapsed", "path_len", "item", "hint", "found", "label_xy")}
        viz["finder"]["log"] = (s.get("log") or [])[-6:]
        if s.get("looked"):   # every 2 s: the finder's looked-at cells (zlib + packbits), drawn by the viewer
            viz["looked"] = s["looked"]

    def viz_worker():
        while rosless.ok():
            time.sleep(1.0)
            if viz["registry"] is None and viz["finder"] is None:
                continue
            ok, msg = net.call_string(gw, "room_finder/viz", json.dumps(viz), 2.0)
            if not ok:
                logging.debug("viz not delivered: %s" % msg)
    router.subscribe("/room_finder/registry", on_registry)
    router.subscribe("/room_finder/status", on_finder)
    threading.Thread(target=viz_worker, daemon=True).start()

    # ---- detection debug image (left | front | right with boxes) as an MJPEG stream; the robot PC forwards the port to the wifi
    dbg = None
    if a.debug_port or a.log_debug_hz > 0:
        import debug_stream
        dbg = debug_stream.DebugStream(a.debug_port)
        router.subscribe("/room_finder/debug_image", dbg.on_image)

    # ---- the nodes (imported unchanged from ReasonNav)
    rosless.install(router)
    sys.path.insert(0, a.mmdev)
    sys.path.insert(0, os.path.join(a.mmdev, "nodes"))
    apply_rig(rig)
    if a.dummy_vlm:
        install_dummy_vlm()
    ws = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))   # the workspace holding this script
    out = a.out_dir or os.path.join(ws, "log", "room_finder_net", "%s_T%s" % (time.strftime("%Y%m%d_%H%M%S"), a.target))
    os.makedirs(out, exist_ok=True)
    if dbg is not None and a.log_debug_hz > 0:   # t_robot: the robot PC clock (odometry offset), to line up with the gateway's --log-dir
        dbg.record(os.path.join(out, "debug_image"), a.log_debug_hz,
                   clock=lambda: None if poses.offset is None else time.time() - poses.offset)
    if oak is not None:
        oak.expo_file = open(os.path.join(out, "camera_exposure.jsonl"), "a")
    yolo = a.yolo
    if not yolo:   # the copy shipped in the ReasonNav checkout, else the training machine's path
        cand = os.path.abspath(os.path.join(a.mmdev, "..", "..", "room_finder_assets", "weights", "doordetect_oi", "best.pt"))
        yolo = cand if os.path.exists(cand) else "/home/user/yolo_ws/runs/doordetect_oi/weights/best.pt"
        # a TensorRT fp16 build of it next to it wins (Jetson: 42 vs 60 ms per 12 MP frame, and it leaves GPU time to GDINO):
        # yolo export model=best.pt format=engine half=True imgsz=960 -> rename to best_960_fp16.engine
        trt = os.path.join(os.path.dirname(yolo), "best_960_fp16.engine")
        yolo = trt if os.path.exists(trt) else yolo
    if not a.env_key:   # a stale OPENAI_API_KEY in the shell must not shadow mm_dev/config/.env
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.setdefault("REASONNAV_ENV", os.path.join(a.mmdev, "config", ".env"))   # the VLM's own default is the dev PC's path
    rosless.Node.param_overrides = {
        "room_perception": {"out_dir": out + "/perception", "yolo_weights": yolo,
                            # one camera per call, round robin. 0 = no wait: each camera's newest frame once, GDINO_WORKERS requests in
                            # flight (~1 Hz per camera with the 960x720 engine: gdino_trt/build_engine.sh, W=960 H=720 SHORT=720)
                            "gdino_hz": float(os.environ.get("GDINO_HZ", "0")),
                            "gdino_workers": int(os.environ.get("GDINO_WORKERS", "2")),
                            "gdino_width": int(os.environ.get("GDINO_WIDTH", "960")),   # must match the engine's image size
                            # pixel thresholds are given at 1280 px width; IMX378 (82.7 deg) at 1280 px: a 40 cm strip sign is ~116 px at 2.5 m.
                            # 90 keeps the OV9782's cut (70 at 97 deg): signs count from ~3.2 m
                            "sign_min_px": float(os.environ.get("SIGN_MIN_PX", "90")),
                            # Tesseract word-count gate before the VLM sign read: off. On the 10-28 crops it passed 1 of 33 signs the VLM
                            # read correctly (the T1xx~T1xx strips, Korean text), and three misses mark a sign "not a sign" for good
                            "sign_ocr_words": int(os.environ.get("SIGN_OCR_WORDS", "0")),
                            # crops for the VLM with median luma below this get a luma stretch + CLAHE (dim corridor, backlit doors:
                            # 129 of 433 crops of the 11-04 T136 run had a median below 50 and the VLM read none of them); 0 = off
                            "dark_enhance": float(os.environ.get("DARK_ENHANCE", "70")),
                            # a later comparable sign read replaces unconfirmed entries (11-04 T140: T131~T150 was also kept as
                            # "T135-T150" and "101~110" from two misreads); entries read the same way twice stay
                            "sign_overwrite": os.environ.get("SIGN_OVERWRITE", "1") == "1",
                            # scene-text OCR server (ai_pc/ocr_server.py, ~/ocr_venv): room-number texts become plate reads directly.
                            # On the 11-10 recording it read all 16 plates the robot passed; GDINO missed plates next to bigger nameplates.
                            # Not running = a warning every 30 s and plates from GDINO + VLM only. "" = off
                            "ocr_url": os.environ.get("OCR_URL", "http://127.0.0.1:8767"),
                            "ocr_min_conf": float(os.environ.get("OCR_MIN_CONF", "0.9")),
                            # GDINO plate boxes -> VLM: off (11-10 18:14 / 18:40 / 18:58: 189-414 VLM calls a run for 5-13 reads; every
                            # number it read twice that the OCR never read was a misread: 0119, 1117, 1116, 121). Signs still use GDINO
                            "gdino_plates": os.environ.get("GDINO_PLATES", "0") == "1",
                            # an OCR number counts once the VLM, shown the frame around it, calls it a room plate (11-10: '2026' on a
                            # poster and the 0119 of an emergency phone sticker became rooms). Off with the dummy VLM (it cannot confirm)
                            "ocr_verify": os.environ.get("OCR_VERIFY", "1") == "1" and not a.dummy_vlm,
                            "door_min_valid": float(os.environ.get("DOOR_MIN_VALID", "0.5")),
                            "label_nearest_door": os.environ.get("LABEL_NEAREST_DOOR", "1") == "1",
                            # detections beyond 5 m are ignored (door / plate / sign positions and sizes are least accurate there)
                            "det_range": float(os.environ.get("DET_RANGE", "5.0")),
                            "read_range": float(os.environ.get("READ_RANGE", "5.0")),
                            "sign_range": float(os.environ.get("SIGN_RANGE", "5.0")),
                            # an oblique view of a sign gives a wrong plane normal, and the arrow bearing is built from it
                            "sign_max_angle_deg": float(os.environ.get("SIGN_MAX_ANGLE_DEG", "50")),
                            # 30 % of the box width left / right of a sign for the VLM: GDINO boxes hug the text and cut the arrow at the
                            # strip's end (11-10 18:40: the bent arrow of 'T112~T121' was half cut and read as plain 'left')
                            "sign_crop_mx": float(os.environ.get("SIGN_CROP_MX", "0.3"))},
        "room_finder": {"target": a.target, "out_dir": out + "/finder", "max_time": float(a.max_time), "policy": a.policy,
                        # real robot: a door needs a mapped wall next to it; go to a door without turning to face it (3 cameras)
                        "door_wall_max": float(os.environ.get("DOOR_WALL_MAX", "0.5")),
                        "door_face": os.environ.get("DOOR_FACE", "0") == "1",
                        # unread lobby signs / doors outscored every frontier; favour frontiers that lead toward the hint
                        "frontier_hint_bonus": float(os.environ.get("FRONTIER_HINT_BONUS", "40")),
                        # dwelling at a sign / door to read it must not count as "stuck" on the next goal (it blocks that goal for 150 s)
                        "stuck_per_item": os.environ.get("STUCK_PER_ITEM", "1") == "1",
                     # a door / sign within 2 m is already in view of the 3 cameras: mark it seen after a short dwell instead of driving to the viewpoint
                     "view_obj_dist": float(os.environ.get("VIEW_OBJ_DIST", "2.0")),
                     "view_dwell": float(os.environ.get("VIEW_DWELL", "1.0")),
                     # optional: items behind the travel direction lose points (off; PASS_SEEN_S is the preferred fix for going back and forth)
                     "backtrack_penalty": float(os.environ.get("BACKTRACK_PENALTY", "0")),
                     # a sign / door that was within view_obj_dist for this long while driving by is already read: do not go back to it
                     # exploring a frontier had no reward: unread signs (+27) and doors always won, so the robot circled the lobby
                     "frontier_bonus": float(os.environ.get("FRONTIER_BONUS", "15")),
                     # a stuck frontier (e.g. the far end of a corridor) is retried after 20 s instead of 150 s
                     "frontier_block_s": float(os.environ.get("FRONTIER_BLOCK_S", "20")),
                     # plates read near the target number give a direction (T101 -15 m, T103 -25 m -> T106 near -40 m): frontiers / doors toward it gain, away lose
                     "trend_weight": float(os.environ.get("TREND_WEIGHT", "0")),
                     # the VLM gets rules for reading sign entries / plates and its earlier answers; signs listing the target are photographed first
                     "belief_guide": os.environ.get("BELIEF_GUIDE", "1") == "1",
                     "belief_weight": float(os.environ.get("BELIEF_WEIGHT", "100")),
                     # the VLM also names a map position for the goal (e.g. the hallway a T101~T126 sign points into): a blob in the confidence grid
                     "belief_point": os.environ.get("BELIEF_POINT", "1") == "1",
                     # the VLM put the T101~T126 goal in the open lobby north of the sign: the frontier openings are lettered on its map, it names the one
                     # to drive through (a sign stands at the hallway it points into; plates read in a hallway beat an arrow)
                     "belief_openings": os.environ.get("BELIEF_OPENINGS", "1") == "1",
                     # 11-04 T113: the west corridor end (2 m wide, walls inflated) had a 4-cell traversable frontier, dropped as noise
                     "frontier_on_free": os.environ.get("FRONTIER_ON_FREE", "1") == "1",
                     # VLM goals inside the looked-at area are moved on along robot -> goal (no confidence lands on looked cells)
                     "goal_unlooked": os.environ.get("GOAL_UNLOOKED", "1") == "1",
                     # a VLM goal gets the weight (answers among the last 4 that point within 10 m of it) / 4 (11-04 T113: three answers
                     # in a row claimed the numbers grow eastward and sent the robot into the wrong wing); 0 = off
                     "belief_consensus": int(os.environ.get("BELIEF_CONSENSUS", "4")),
                     # signs / doors are read on the way only: visited when the path there is <= 4 m and not behind the direction of
                     # travel (unlimited visits sent the robot back and forth in the lobby, none at all left the lobby signs unread, 11-10).
                     # Plates one digit off the target are not visited; a read of the target itself is still checked
                     "visit_signs": os.environ.get("VISIT_SIGNS", "1") == "1",
                     "visit_doors": os.environ.get("VISIT_DOORS", "1") == "1",
                     "visit_labels": os.environ.get("VISIT_LABELS", "0") == "1",
                     "visit_max_pc": float(os.environ.get("VISIT_MAX_PC", "4")),
                     "visit_no_back": os.environ.get("VISIT_NO_BACK", "1") == "1",
                     # stand still 1.5 s next to an unread door / plate / sign within 2.5 m, once each: the waypoints have no speed limit
                     "look_stop_s": float(os.environ.get("LOOK_STOP_S", "1.5")),
                     "look_stop_m": float(os.environ.get("LOOK_STOP_M", "2.5")),
                     # 'looked at' = within 3 m of the path (through walls), plus 6 m in line of sight where it is >= 2 m from walls (the
                     # lobby). 11-10: 5 m line of sight everywhere dismissed the right VLM goal 4 m away and never covered the walls' edges
                     "look_radius": float(os.environ.get("LOOK_RADIUS", "3.0")),
                     "look_far": float(os.environ.get("LOOK_FAR", "6.0")),
                     "look_open_m": float(os.environ.get("LOOK_OPEN_M", "1.5")),
                     # sign arrows point at a corridor mouth 1-4 m away, the corridor runs across: the arrow becomes that corridor, and the
                     # corridors of entries without the target cost candidates 40 points (11-10: 'T131~T150' read at 17 s, robot still
                     # drove to the east corridor's end; 'T101~T126' sent it north into the lobby instead of west)
                     "sign_corridor": os.environ.get("SIGN_CORRIDOR", "1") == "1",
                     "sign_neg_penalty": float(os.environ.get("SIGN_NEG_PENALTY", "40")),
                     # the most specific entry listing the target gets the full sign weight, broader ones 1/4 (18:08: 'T112~T126' south
                     # outweighed 'T112~T121' west at T112, and the robot went south)
                     "sign_broad_w": float(os.environ.get("SIGN_BROAD_W", "1.0")),
                     # path cost per cell 1 + 1.5 * (0.9 m - clearance) instead of 6x: a 2 m corridor cost ~4.5x its length (18:08: the
                     # frontier 4.5 m down the T112 corridor lost to one 12 m away in the hall)
                     "soft_weight": float(os.environ.get("SOFT_WEIGHT", "1.5")),
                     # passages >= 2 x 0.57 m wide are traversable, measured from where the lidar points hit (gateway --map-res 0.05,
                     # --subcell 1 = default), whatever the inflation: 1.10 / 1.12 m blocked, 1.2 m passable at any wall angle (11-11; 0.525
                     # on cell centres let the 1.12 m passage at (-7.0, -2.7) in). Without hit positions a wall is only known to the
                     # cell (0.575 at most on 5 cm, 0.5 on 10 cm; a warning). TRAV_OCC_M=0 goes back to TRAV_CLEAR on the inflated map
                     "trav_occ_m": float(os.environ.get("TRAV_OCC_M", "0.57")),
                     # the finder's own grid: a 5 cm map is folded into 10 cm cells once the passage widths are taken from it
                     "grid_res": float(os.environ.get("FINDER_GRID_RES", "0.1")),
                     # (TRAV_OCC_M=0 only) traversable = free and >= 0.1 m from the gateway's inflated cells: ~1.0 m passages on
                     # --inflate 0.4, ~1.3 m on 0.5 (the 11-10 runs). Was 0.3 on 0.5: ~1.6 m
                     "trav_clear": float(os.environ.get("TRAV_CLEAR", "0.1")),
                     # no free spot 1-2 m in front of a plate (2 m corridor): the nearest traversable cell within 2.5 m is the viewpoint
                     # (18:08: T113 read once by the OCR at 0.8 m, re-reading it never became a candidate)
                     "viewpoint_fallback_m": float(os.environ.get("VIEWPOINT_FALLBACK_M", "2.5")),
                     # VLM goals ignored as already looked at are re-checked once (low score) before giving up (18:08: the VLM named
                     # T113's spot 7 times; the robot gave up 6 m from it)
                     "relook": os.environ.get("RELOOK", "1") == "1",
                     # a frontier's goal point is its cheapest cell >= 1.5 m away: a corridor's frontier starts at the robot and its nearest
                     # cell (< 0.8 m) used to drop the whole frontier (11-10 T113: turned back out of the west corridor at x -26)
                     "frontier_min_dist": float(os.environ.get("FRONTIER_MIN_DIST", "1.5")),
                     # unread signs scored 30 - path everywhere, so the lobby's decorations kept winning: lower base, plus the belief at the sign
                     "sign_base": float(os.environ.get("SIGN_BASE", "10")),
                     "sign_belief_w": float(os.environ.get("SIGN_BELIEF_W", "30")),
                     # frontiers vanish when the lidar already sees down a corridor; the VLM's predicted place (belief peak) is a goal of its own
                     "belief_peak": os.environ.get("BELIEF_PEAK", "1") == "1",
                     # signs / doors in an area the robot has already been within 3 m of are not visited again
                     "skip_looked": os.environ.get("SKIP_LOOKED", "0") == "1",       # old 3 m rule, off: the 2 m + camera view rule below is used
                     # doors / signs farther than this from any traversable cell are ignored (room plates are always kept, ReasonNav
                     # 3450477). The gateway inflates walls by
                     # 0.5 m and the finder keeps 0.3 m clearance, so traversable cells start ~0.8 m from a wall: at 1.0 m the plates
                     # on the walls were dropped (11-04 T145: T146 next to the target, T101/T102 in the west corridor). 1.5 m = ~0.7 m
                     # beyond the wall line
                     "det_reach_m": float(os.environ.get("DET_REACH_M", "1.5")),
                     # corridor: the frontier ahead flickers away as the lidar sees further, and the only candidate left is a far one behind (turn around, then back)
                     "frontier_match_m": float(os.environ.get("FRONTIER_MATCH_M", "6.0")),
                     "frontier_hold_s": float(os.environ.get("FRONTIER_HOLD_S", "12")),
                     # a person walking by can hold the robot up: only call it stuck after this many seconds without moving
                     "stuck_s": float(os.environ.get("STUCK_S", "45")),
                     "pass_seen_s": float(os.environ.get("PASS_SEEN_S", "0.5")),
                     # seen = within VIEW_OBJ_DIST (2 m) and inside the 3 cameras' view (yaw 0 / +-90 deg, IMX378 lens edges at +-47 deg -> half angle ~137 deg)
                     "view_half_fov": math.radians(float(os.environ.get("VIEW_HALF_FOV_DEG", "137"))),
                        "belief_signs": a.belief_signs,
                        "belief_commit": os.environ.get("BELIEF_COMMIT", "true").lower() == "true",
                        "belief_range": float(os.environ.get("BELIEF_RANGE", "25")),
                        "belief_numbers": os.environ.get("BELIEF_NUMBERS", "false").lower() == "true",
                        "belief_verify_base": float(os.environ.get("BELIEF_VERIFY_BASE", "0")),
                        "belief_verify_max": float(os.environ.get("BELIEF_VERIFY_MAX", "15")),
                        "belief_alpha": float(os.environ.get("BELIEF_ALPHA", "0.92")),
                        "exit_when_done": bool(a.exit_when_done)},
    }
    for kv in filter(None, os.environ.get("RF_PARAMS", "").split(",")):   # RF_PARAMS="room_finder.sign_seek=100,room_finder.sign_lock=true"
        k, v = kv.split("=", 1)
        node, name = k.split(".", 1)
        v = {"true": True, "false": False}.get(v.lower(), v)
        try:
            v = float(v) if isinstance(v, str) else v
        except ValueError:
            pass
        rosless.Node.param_overrides.setdefault(node, {})[name] = v
    # the GDINO and OCR servers must be up: 11-10 17:17 ran without the OCR server (no plate read by it) and nobody noticed
    po = rosless.Node.param_overrides.get("room_perception", {})
    wait_servers([("GDINO", str(po.get("gdino_url") or "http://127.0.0.1:8765")), ("OCR", str(po.get("ocr_url") or ""))])
    import room_perception  # noqa: E402
    import room_finder  # noqa: E402
    perception = room_perception.RoomPerception()
    finder = room_finder.RoomFinder()
    logging.info("perception + finder up (target %s, out %s)" % (a.target, out))
    rosless.spin()
    if oak is not None:
        oak.close()
    net.close()
    os._exit(0)


if __name__ == "__main__":
    main()
