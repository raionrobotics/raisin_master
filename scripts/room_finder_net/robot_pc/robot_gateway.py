#!/usr/bin/env python3
"""Robot PC side of the room finder (raisin_network only, no ROS 2).

Runs next to the robot's raisin node and does the three things the AI PC should not do over the network:

  1. goal point  : service `room_finder/goal` (JSON {x, y, yaw, use_yaw}) -> raisin `planning/set_waypoints`
                   (the navigation plugin plans + drives).  Goals are sanity-checked (finite, within --max-goal-dist of the
                   robot) and a watchdog cancels the goal when the AI PC stops sending goals (link lost, crash, finished).
  2. exploration map : occupancy grid (unknown = -1, free 0, inflated 99, obstacle 100) accumulated here from the lidar_slam
                   registered cloud like nav2's obstacle layer (rays <= 10 m, sector +-135 deg, obstacle band around the lidar
                   height, 0.5 m inflation) and published as `room_finder/map` -- a compact grid instead of raw clouds.
  3. status      : `room_finder/status` JSON (pose, has_goal, watchdog state), 2 Hz.
  4. map viewer  : http://<robot PC>:8081 (--viz-port) -- map, robot trail, goal and the AI PC's landmarks (doors, room
                   numbers, signs), which the AI PC pushes through service `room_finder/viz`.  Read-only, no camera images.
  Service `room_finder/stop` cancels the current goal.

  robot_gateway.py --robot-id <robot nickname> [--id room_finder_gw] [--iface lo]
"""
import argparse
import base64
import json
import logging
import math
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "raisin_py", "build"))   # built module; PYTHONPATH also works
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import raisin_boot  # noqa: E402
raisin_boot.preload()
import raisin_py  # noqa: E402


def disk_dilate(mask, rad):
    """binary dilation of `mask` with a disk of `rad` cells (numpy only)"""
    out = mask.copy()
    h, w = mask.shape
    for dy in range(-rad, rad + 1):
        for dx in range(-rad, rad + 1):
            if (dy == 0 and dx == 0) or dy * dy + dx * dx > rad * rad:
                continue
            out[max(dy, 0):h + min(dy, 0), max(dx, 0):w + min(dx, 0)] |= mask[max(-dy, 0):h + min(-dy, 0), max(-dx, 0):w + min(-dx, 0)]
    return out


class Gateway:
    def __init__(self, a):
        self.a = a
        self.lock = threading.Lock()
        self.pose = None            # (x, y, z, yaw, stamp)
        self.frame = None           # frame id of the robot's navigation pose = frame of the waypoints
        self.has_goal = False
        self.goal = None
        self.last_goal_t = 0.0
        self.watchdog_fired = False
        self.pending = None         # latest goal waiting to be sent: (x, y, yaw, use_yaw)
        self.cv = threading.Condition()
        self.sent = 0
        # map
        res = a.map_res
        self.res = res
        xmin, ymin, xmax, ymax = a.map_bounds
        self.x0, self.y0 = xmin, ymin
        self.w, self.h = int(math.ceil((xmax - xmin) / res)), int(math.ceil((ymax - ymin) / res))
        self.logodds = np.zeros((self.h, self.w), dtype=np.float32)
        self.map_lock = threading.Lock()
        self.n_bins = 720
        self.scans = 0
        # viewer state
        self.viz = {}               # latest landmarks + finder state from the AI PC
        self.viz_t = 0.0
        self.trail = []             # robot xy every >= 0.2 m
        self.map_viz = None         # (json bytes) latest cropped map for the viewer

        self.net = raisin_py.Net(a.id, a.iface)
        self.robot = None
        while self.robot is None:
            self.robot = self.net.connect(a.robot_id)
            if self.robot is None:
                logging.info("waiting for robot '%s'" % a.robot_id)
                time.sleep(1.0)
        logging.info("connected to robot '%s'" % a.robot_id)
        self.net.subscribe_odometry(self.robot, a.odom_topic, self.on_odom)
        self.net.subscribe_cloud(self.robot, a.cloud_topic, self.on_cloud)
        self.net.subscribe_nav_status(self.robot, a.status_topic, self.on_status)
        self.pub_map = self.net.publisher_grid("room_finder/map")
        self.pub_status = self.net.publisher_string("room_finder/status")
        self.net.service_string("room_finder/goal", self.srv_goal)
        self.net.service_string("room_finder/stop", self.srv_stop)
        self.net.service_string("room_finder/viz", self.srv_viz)
        threading.Thread(target=self.sender, daemon=True).start()
        threading.Thread(target=self.loop, daemon=True).start()
        if a.viz_port:
            threading.Thread(target=self.serve_viewer, daemon=True).start()
        logging.info("map: rays <= %.1f m, scan sector +-%.0f deg, obstacles %.2f m below .. %.2f m above the lidar (lidar %.3f m above odom), inflation %.2f m"
                     % (a.scan_range, a.scan_fov, a.obstacle_below, a.obstacle_above, a.lidar_z, a.inflate))
        logging.info("gateway up: goals -> %s (frame from %s), map %dx%d @ %.2f m, watchdog %.0f s"
                     % (a.waypoint_service, a.odom_topic, self.w, self.h, res, a.watchdog))

    # ---------------------------------------------------------------- robot data
    def on_odom(self, stamp, frame, pq, _tw):
        x, y, z, qx, qy, qz, qw = pq
        yaw = math.atan2(2 * (qw * qz + qx * qy), 1 - 2 * (qy * qy + qz * qz))
        with self.lock:
            self.pose, self.frame = (x, y, z, yaw, stamp), frame
            if not self.trail or math.hypot(x - self.trail[-1][0], y - self.trail[-1][1]) >= 0.2:
                self.trail.append((round(x, 2), round(y, 2)))
                if len(self.trail) > 20000:
                    self.trail = self.trail[::2]

    def on_status(self, has_goal, has_plan, idx, count):
        with self.lock:
            self.has_goal = bool(has_goal)

    def on_cloud(self, stamp, frame, pts):
        """nav2 obstacle-layer style: points within a height band around the lidar, inside the scan sector and range, mark
        obstacles; a ray to the nearest hit per azimuth (at most --scan-range) clears free space; the rest stays unknown"""
        with self.lock:
            pose = self.pose
        if pose is None or len(pts) == 0:
            return
        rx, ry, rz, yaw = pose[0], pose[1], pose[2], pose[3]
        a = self.a
        rel = pts - np.array([rx, ry, rz + a.lidar_z], dtype=np.float32)   # relative to the lidar
        rel = rel[(rel[:, 2] >= -a.obstacle_below) & (rel[:, 2] <= a.obstacle_above)]
        if len(rel) < 30:
            return
        r = np.hypot(rel[:, 0], rel[:, 1])
        az = np.arctan2(rel[:, 1], rel[:, 0])
        az_rel = (az - yaw + math.pi) % (2 * math.pi) - math.pi            # angle from the robot's heading
        keep = (r > 0.35) & (np.abs(az_rel) <= math.radians(a.scan_fov))
        rel, r, az = rel[keep], r[keep], az[keep]
        if len(rel) == 0:
            return
        b = ((az + math.pi) / (2 * math.pi) * self.n_bins).astype(np.int64) % self.n_bins
        rmin = np.full(self.n_bins, np.inf, dtype=np.float32)
        np.minimum.at(rmin, b, r)
        res, rng = self.res, a.scan_range
        ang = (np.arange(self.n_bins) + 0.5) / self.n_bins * 2 * math.pi - math.pi
        reach = np.where(np.isfinite(rmin), np.minimum(rmin - 1.5 * res, rng), 0.0).clip(0.0, rng)
        ks = np.arange(0.0, rng, res * 0.7, dtype=np.float32)
        ok = ks[None, :] <= reach[:, None]
        fx = rx + np.cos(ang)[:, None] * ks[None, :]
        fy = ry + np.sin(ang)[:, None] * ks[None, :]
        ix = np.floor((fx[ok] - self.x0) / res).astype(np.int64)
        iy = np.floor((fy[ok] - self.y0) / res).astype(np.int64)
        inside = (ix >= 0) & (ix < self.w) & (iy >= 0) & (iy < self.h)
        free_idx = np.unique(iy[inside] * self.w + ix[inside])
        rel = rel[r <= rng]                                                # obstacles are only marked within the range
        hx = np.floor((rx + rel[:, 0] - self.x0) / res).astype(np.int64)
        hy = np.floor((ry + rel[:, 1] - self.y0) / res).astype(np.int64)
        hin = (hx >= 0) & (hx < self.w) & (hy >= 0) & (hy < self.h)
        hit_idx = np.unique(hy[hin] * self.w + hx[hin])
        with self.map_lock:
            flat = self.logodds.reshape(-1)
            flat[free_idx] = np.maximum(flat[free_idx] - 0.35, -4.0)
            flat[hit_idx] = np.minimum(flat[hit_idx] + 0.9, 4.0)
            self.scans += 1

    def publish_map(self):
        if self.scans == 0:
            return
        with self.map_lock:
            lo = self.logodds
            known = np.abs(lo) > 0.05
            rows, cols = np.flatnonzero(known.any(axis=1)), np.flatnonzero(known.any(axis=0))
            if len(rows) == 0:
                return
            r0, r1 = max(rows[0] - 5, 0), min(rows[-1] + 6, self.h)
            c0, c1 = max(cols[0] - 5, 0), min(cols[-1] + 6, self.w)
            sub = lo[r0:r1, c0:c1].copy()
        data = np.full(sub.shape, -1, dtype=np.int8)
        data[sub <= -0.4] = 0
        occ = sub >= 0.85
        rad = int(round(self.a.inflate / self.res))
        if rad > 0:   # like nav2's inflation layer: known cells within --inflate of an obstacle get 99 (inscribed), obstacles 100
            data[disk_dilate(occ, rad) & (data == 0)] = 99
        data[occ] = 100
        x0, y0 = float(self.x0 + c0 * self.res), float(self.y0 + r0 * self.res)
        self.pub_map.publish("map", self.res, x0, y0, data)
        if self.a.viz_port:   # viewer: 0 free, 100 occupied, 255 unknown, row 0 = lowest y
            self.map_viz = json.dumps({"res": self.res, "x0": x0, "y0": y0, "w": int(data.shape[1]), "h": int(data.shape[0]),
                                       "data": base64.b64encode(data.view(np.uint8).tobytes()).decode()}).encode()

    # ---------------------------------------------------------------- goals
    def srv_goal(self, payload):
        try:
            g = json.loads(payload)
            x, y = float(g["x"]), float(g["y"])
            yaw, use_yaw = float(g.get("yaw", 0.0)), bool(g.get("use_yaw", False))
        except Exception as e:  # noqa: BLE001
            return False, "bad goal: %r" % e
        with self.lock:
            pose = self.pose
        if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(yaw)):
            return False, "non-finite goal"
        if pose is None:
            return False, "no robot pose yet"
        d = math.hypot(x - pose[0], y - pose[1])
        if d > self.a.max_goal_dist:
            return False, "goal %.1f m away (limit %.1f m)" % (d, self.a.max_goal_dist)
        with self.cv:
            self.pending = (x, y, yaw, use_yaw)
            self.last_goal_t, self.watchdog_fired = time.time(), False
            self.cv.notify()
        return True, "accepted"

    def srv_viz(self, payload):
        try:
            v = json.loads(payload)
        except Exception as e:  # noqa: BLE001
            return False, "bad viz: %r" % e
        self.viz, self.viz_t = v, time.time()
        return True, "ok"

    # ---------------------------------------------------------------- map viewer (http)
    def state_json(self):
        with self.lock:
            p, hg, trail = self.pose, self.has_goal, list(self.trail)
        return json.dumps({"t": time.time(), "pose": None if p is None else [round(v, 3) for v in p[:4]], "has_goal": hg,
                           "goal": self.goal, "watchdog_fired": self.watchdog_fired, "scans": self.scans, "trail": trail,
                           "viz": self.viz, "viz_age": None if not self.viz_t else round(time.time() - self.viz_t, 1)}).encode()

    def serve_viewer(self):
        gw = self
        page = os.path.join(os.path.dirname(os.path.abspath(__file__)), "viewer.html")

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, body, ctype):
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path in ("/", "/index.html"):
                    self._send(open(page, "rb").read(), "text/html; charset=utf-8")
                elif path == "/state.json":
                    self._send(gw.state_json(), "application/json")
                elif path == "/map.json":
                    self._send(gw.map_viz or b"null", "application/json")
                else:
                    self.send_error(404)

        srv = ThreadingHTTPServer((self.a.viz_host, self.a.viz_port), H)
        logging.info("map viewer: http://%s:%d" % (self.a.viz_host, self.a.viz_port))
        srv.serve_forever()

    def srv_stop(self, _payload):
        with self.cv:
            self.pending = ("stop",)
            self.cv.notify()
        return True, "stopping"

    def sender(self):
        """latest goal wins; the (blocking) set_waypoints call never runs on a raisin service thread"""
        while True:
            with self.cv:
                while self.pending is None:
                    self.cv.wait(1.0)
                item, self.pending = self.pending, None
            with self.lock:
                frame = self.frame
            if frame is None:
                continue
            if item[0] == "stop":
                ok, msg = self.net.call_set_waypoints(self.robot, self.a.waypoint_service, [], 5.0)
                self.goal = None
            else:
                x, y, yaw, use_yaw = item
                ok, msg = self.net.call_set_waypoints(self.robot, self.a.waypoint_service, [(frame, x, y, use_yaw, yaw)], 5.0)
                self.goal = (x, y, yaw)
            self.sent += 1
            if not ok:
                logging.warning("set_waypoints failed: %s" % msg)

    def loop(self):
        t_map = t_stat = 0.0
        while True:
            time.sleep(0.1)
            now = time.time()
            if self.goal is not None and not self.watchdog_fired and now - self.last_goal_t > self.a.watchdog:
                logging.warning("watchdog: no goal from the AI PC for %.0f s -> cancel the goal" % self.a.watchdog)
                self.watchdog_fired = True
                with self.cv:
                    self.pending = ("stop",)
                    self.cv.notify()
            if now - t_map > 1.0 / self.a.map_hz:
                t_map = now
                try:
                    self.publish_map()
                except Exception:  # noqa: BLE001
                    logging.exception("map")
            if now - t_stat > 0.5:
                t_stat = now
                with self.lock:
                    p, hg = self.pose, self.has_goal
                self.pub_status.publish(json.dumps({
                    "t": now, "pose": None if p is None else [round(v, 3) for v in p[:4]], "has_goal": hg, "goal": self.goal,
                    "goals_sent": self.sent, "watchdog_fired": self.watchdog_fired, "scans": self.scans}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--robot-id", required=True, help="raisin network id of the robot's main node (robot_nickname)")
    ap.add_argument("--id", default="room_finder_gw")
    ap.add_argument("--iface", nargs="*", default=["lo"])
    ap.add_argument("--odom-topic", default="/Odometry/base")
    ap.add_argument("--cloud-topic", default="cloud_registered")
    ap.add_argument("--status-topic", default="navigation/status")
    ap.add_argument("--waypoint-service", default="planning/set_waypoints")
    ap.add_argument("--max-goal-dist", type=float, default=8.0, help="reject goals farther than this from the robot (m)")
    ap.add_argument("--watchdog", type=float, default=10.0, help="cancel the goal after this many seconds without a new goal")
    ap.add_argument("--map-res", type=float, default=0.1)
    ap.add_argument("--map-hz", type=float, default=2.0)
    ap.add_argument("--map-bounds", type=float, nargs=4, default=[-52.0, -8.0, 30.0, 40.0], metavar=("XMIN", "YMIN", "XMAX", "YMAX"),
                    help="area (m, navigation frame) the map covers; default = the simulated hospital")
    ap.add_argument("--scan-range", type=float, default=10.0, help="rays / obstacle marking reach at most this far (m)")
    ap.add_argument("--scan-fov", type=float, default=135.0, help="scan sector: +-this many degrees around the robot's heading")
    ap.add_argument("--lidar-z", type=float, default=0.2238272514, help="height of the lidar above the odometry origin = the IMU (m)")
    ap.add_argument("--obstacle-below", type=float, default=0.3, help="obstacle band: this far below the lidar (m)")
    ap.add_argument("--obstacle-above", type=float, default=0.3, help="obstacle band: this far above the lidar (m)")
    ap.add_argument("--inflate", type=float, default=0.5, help="inflation radius around obstacles (m), 0 = off")
    ap.add_argument("--viz-port", type=int, default=8081, help="map viewer http port (0 = off)")
    ap.add_argument("--viz-host", default="0.0.0.0", help="address the viewer listens on")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    Gateway(a)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    os._exit(0)


if __name__ == "__main__":
    main()
