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
        if text.startswith("The image is a crop of a hospital wall"):
            return '{"number": null, "confidence": 0.0}'
        if text.startswith("The image is a crop of a navigational sign"):
            return "[]"
        return '{"region": "", "patterns": "dummy VLM", "reasoning": "dummy VLM"}'

    V.VLM.__init__, V.VLM._complete = init, complete
    logging.warning("DUMMY VLM: no OpenAI calls; room numbers cannot be read through the VLM")


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
                       "cues": [{k: c.get(k) for k in ("place", "bearing", "lo", "hi", "pre")} for c in s.get("cues", [])]}
                      for s in r.get("signs", [])]}

    def on_finder(m):
        s = json.loads(m.data)
        viz["finder"] = {k: s.get(k) for k in ("state", "target", "elapsed", "path_len", "item", "hint", "found", "label_xy")}
        viz["finder"]["log"] = (s.get("log") or [])[-6:]

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
    if a.debug_port:
        import debug_stream
        router.subscribe("/room_finder/debug_image", debug_stream.DebugStream(a.debug_port).on_image)

    # ---- the nodes (imported unchanged from ReasonNav)
    rosless.install(router)
    sys.path.insert(0, a.mmdev)
    sys.path.insert(0, os.path.join(a.mmdev, "nodes"))
    apply_rig(rig)
    if a.dummy_vlm:
        install_dummy_vlm()
    out = a.out_dir or os.path.expanduser("~/raisin_ws/log/room_finder_net/%s_T%s" % (time.strftime("%Y%m%d_%H%M%S"), a.target))
    os.makedirs(out, exist_ok=True)
    yolo = a.yolo
    if not yolo:   # the copy shipped in the ReasonNav checkout, else the training machine's path
        cand = os.path.abspath(os.path.join(a.mmdev, "..", "..", "room_finder_assets", "weights", "doordetect_oi", "best.pt"))
        yolo = cand if os.path.exists(cand) else "/home/user/yolo_ws/runs/doordetect_oi/weights/best.pt"
    if not a.env_key:   # a stale OPENAI_API_KEY in the shell must not shadow mm_dev/config/.env
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.setdefault("REASONNAV_ENV", os.path.join(a.mmdev, "config", ".env"))   # the VLM's own default is the dev PC's path
    rosless.Node.param_overrides = {
        "room_perception": {"out_dir": out + "/perception", "yolo_weights": yolo,
                            # one camera per call, round robin; the loop sleeps 1/gdino_hz and then waits for the reply
                            "gdino_hz": float(os.environ.get("GDINO_HZ", "1.0")),
                            # the real cameras are 1280 px wide: a 40 cm strip sign is ~90 px at 2.5 m
                            "sign_min_px": float(os.environ.get("SIGN_MIN_PX", "70")),
                            "door_min_valid": float(os.environ.get("DOOR_MIN_VALID", "0.5"))},
        "room_finder": {"target": a.target, "out_dir": out + "/finder", "max_time": float(a.max_time), "policy": a.policy,
                        "belief_signs": a.belief_signs,
                        "belief_commit": os.environ.get("BELIEF_COMMIT", "true").lower() == "true",
                        "belief_range": float(os.environ.get("BELIEF_RANGE", "25")),
                        "belief_numbers": os.environ.get("BELIEF_NUMBERS", "false").lower() == "true",
                        "belief_verify_base": float(os.environ.get("BELIEF_VERIFY_BASE", "0")),
                        "belief_verify_max": float(os.environ.get("BELIEF_VERIFY_MAX", "15")),
                        "belief_alpha": float(os.environ.get("BELIEF_ALPHA", "0.92")),
                        "exit_when_done": bool(a.exit_when_done)},
    }
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
