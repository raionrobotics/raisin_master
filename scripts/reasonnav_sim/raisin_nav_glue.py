#!/usr/bin/env python3
"""Glue between ReasonNav (ROS 2 / nav2 API) and raisin navigation, on top of raisin_bridge.

raisin_bridge mirrors topics/services 1:1 by name, so ReasonNav's expectations are met here:
  * TF        : map -> odom (identity), odom -> base_link (from /Odometry/state_estimator),
                base_link -> oak_front|oak_left|oak_right and livox_frame (static, from the raibo2 modules)
  * cameras   : CameraInfo for the three OAK-D Pro W (oak_front/left/right; raisin publishes only images)
  * costmap   : /navigation/global_costmap -> /global_costmap/costmap re-stamped in the map frame
  * goals     : nav2 actions navigate_to_pose / spin -> raisin service /planning/set_waypoints,
                completion taken from /navigation/status
Velocity commands are NOT bridged: raisin's navigation stack drives the robot.
"""
import math
import threading
import time

import numpy as np
import rclpy
from rclpy.action import ActionServer, CancelResponse, GoalResponse
from rclpy.callback_groups import ReentrantCallbackGroup
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy

from geometry_msgs.msg import PoseStamped, TransformStamped
from nav_msgs.msg import Odometry, OccupancyGrid
from nav2_msgs.action import NavigateToPose, Spin
from sensor_msgs.msg import CameraInfo, Image, PointCloud2
from tf2_ros import TransformBroadcaster, StaticTransformBroadcaster

from raisin_interfaces.msg import NavigationStatus, Waypoint
from raisin_interfaces.srv import SetWaypoints


def yaw_of(q):
    return math.atan2(2.0 * (q.w * q.z + q.x * q.y), 1.0 - 2.0 * (q.y * q.y + q.z * q.z))


def wrap(a):
    return (a + math.pi) % (2.0 * math.pi) - math.pi


def camera_info(width, height, fx, fy, cx, cy, frame):
    ci = CameraInfo()
    ci.header.frame_id = frame
    ci.width, ci.height = width, height
    ci.distortion_model = "plumb_bob"
    ci.d = [0.0] * 5
    ci.k = [fx, 0.0, cx, 0.0, fy, cy, 0.0, 0.0, 1.0]
    ci.r = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    ci.p = [fx, 0.0, cx, 0.0, 0.0, fy, cy, 0.0, 0.0, 0.0, 1.0, 0.0]
    return ci


# Camera mast of the simulated raibo (raisin_raibo2/resource/modules/oak_mast + sensors/oakd_pro_w_sim.xml).
# Frames are ROS body convention (x forward, y left, z up) and sit at the colour/depth sensor origin.
MOUNT_XYZ = (-0.0579, 0.0, 1.113)         # TORSO frame; 1.0 m above the top plate (z=0.113)
SENSOR_OFFSET = 0.02                       # sensor origin ahead of the module origin along its own x
LIDAR_FRAME = "livox_frame"
LIDAR_XYZ = (-0.0579, 0.0, 0.209)          # modules/livox_lidar (base_to_lidar)
CAMERAS = {}
for _name, _yaw in (("oak_front", 0.0), ("oak_left", math.pi / 2), ("oak_right", -math.pi / 2)):
    CAMERAS[_name] = {"yaw": _yaw,
                      "xyz": (MOUNT_XYZ[0] + SENSOR_OFFSET * math.cos(_yaw),
                              MOUNT_XYZ[1] + SENSOR_OFFSET * math.sin(_yaw), MOUNT_XYZ[2])}
_HFOV = 1.885                              # colour and depth share this FOV
_fx = lambda w: (w / 2.0) / math.tan(_HFOV / 2.0)  # noqa: E731
COLOR_INTRINSICS = (3840, 2880, _fx(3840), _fx(3840), 1920.0, 1440.0)
DEPTH_INTRINSICS = (640, 480, _fx(640), _fx(640), 320.0, 240.0)


class RaisinNavGlue(Node):
    def __init__(self):
        super().__init__("raisin_nav_glue")
        p = self.declare_parameters("", [
            ("map_frame", "map"),
            ("odom_frame", "odom"),
            ("base_frame", "base_link"),
            ("waypoint_frame", "auto"),        # "auto": use the frame_id of odom_topic (raisin robot id)
            ("odom_topic", "/Odometry/base"),  # lidar_slam odometry = the frame raisin navigation plans in
            ("goal_tolerance", 0.35),
            ("yaw_tolerance", 0.4),
            ("goal_timeout", 300.0),
            # persistent exploration map: raisin tracks no unknown space, so "known" is accumulated by
            # ray casting from the robot pose over the obstacle cells of raisin's costmap relay
            ("map_bounds", [-52.0, -8.0, 30.0, 40.0]),   # xmin ymin xmax ymax (m); hospital bbox + margin
            ("map_publish_rate", 2.0),
            ("spin_legs", 3),                             # a full turn is split into this many yaw waypoints
        ])
        g = lambda n: self.get_parameter(n).value  # noqa: E731
        self.map_frame, self.odom_frame, self.base_frame = g("map_frame"), g("odom_frame"), g("base_frame")
        self.waypoint_frame = g("waypoint_frame")
        self.goal_tol, self.yaw_tol, self.goal_timeout = g("goal_tolerance"), g("yaw_tolerance"), g("goal_timeout")

        self.cb = ReentrantCallbackGroup()
        self.lock = threading.Lock()
        self.odom = None
        self.status = None

        # --- TF
        self.tf = TransformBroadcaster(self)
        self.static_tf = StaticTransformBroadcaster(self)
        static = [self._static(self.map_frame, self.odom_frame, [0, 0, 0], [0, 0, 0]),
                  self._static(self.base_frame, LIDAR_FRAME, LIDAR_XYZ, [0, 0, 0])]
        for name, cam in CAMERAS.items():
            static.append(self._static(self.base_frame, name, cam["xyz"], [0.0, 0.0, cam["yaw"]]))
        self.static_tf.sendTransform(static)
        # raisin_bridge publishes everything with rclcpp::QoS(3).best_effort(); match it or nothing arrives
        bridge_qos = QoSProfile(depth=5, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.pose_frame = None  # frame_id reported by odom_topic (raisin's robot network id)
        self.create_subscription(Odometry, g("odom_topic"), self.on_odom, bridge_qos, callback_group=self.cb)
        self.odom_pub = self.create_publisher(Odometry, "/odom", 10)

        # --- camera info for every OAK (raisin publishes images only), stamped like the image it belongs to
        img_qos = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.cam_info, self.cam_info_pub = {}, {}
        for name in CAMERAS:
            for kind, (w, h, fx, fy, cx, cy) in (("rgb", COLOR_INTRINSICS), ("depth", DEPTH_INTRINSICS)):
                self.cam_info[(name, kind)] = camera_info(w, h, fx, fy, cx, cy, name)
                self.cam_info_pub[(name, kind)] = self.create_publisher(CameraInfo, "/%s/%s/camera_info" % (name, kind), 10)
                self.create_subscription(Image, "/%s/%s" % (name, kind),
                                         lambda m, key=(name, kind): self.on_image(key, m), img_qos,
                                         callback_group=self.cb)

        # --- occupancy map built here from the lidar_slam registered cloud (/cloud_registered, world frame):
        # raisin's own costmap is a 5 m rolling window and never reaches the bridge as a grid, and it has no unknown
        # space. Wall-height points stamp obstacles, a ray to the nearest hit per azimuth clears free space,
        # everything else stays unknown (-1) -> real frontiers for exploration.
        map_qos = QoSProfile(depth=1, durability=DurabilityPolicy.TRANSIENT_LOCAL)
        self.costmap_res = float(self.declare_parameter("costmap_resolution", 0.1).value)
        xmin, ymin, xmax, ymax = [float(v) for v in g("map_bounds")]
        self.map_x0, self.map_y0 = xmin, ymin
        self.map_w = int(math.ceil((xmax - xmin) / self.costmap_res))
        self.map_h = int(math.ceil((ymax - ymin) / self.costmap_res))
        self.logodds = np.zeros((self.map_h, self.map_w), dtype=np.float32)
        self.map_lock = threading.Lock()
        self.n_bins = 720
        self.costmap_pub = self.create_publisher(OccupancyGrid, "/global_costmap/costmap", map_qos)
        self.create_subscription(PointCloud2, "/cloud_registered", self.on_cloud, bridge_qos, callback_group=self.cb)
        self.create_timer(1.0 / float(g("map_publish_rate")), self.publish_map, callback_group=self.cb)
        self.map_scans = 0

        # --- direct goal interface for the room finder: a PoseStamped (map frame) becomes a raisin waypoint
        self.create_subscription(PoseStamped, "/room_finder/goal", self.on_goal_pose, 5, callback_group=self.cb)
        self.create_subscription(PoseStamped, "/room_finder/goal_yaw", lambda m: self.on_goal_pose(m, True), 5,
                                 callback_group=self.cb)

        self.spin_legs = int(g("spin_legs"))

        # --- goals
        self.create_subscription(NavigationStatus, "/navigation/status", self.on_status, bridge_qos, callback_group=self.cb)
        self.set_wp = self.create_client(SetWaypoints, "/planning/set_waypoints", callback_group=self.cb)
        self.nav_server = ActionServer(self, NavigateToPose, "navigate_to_pose", self.exec_navigate,
                                       goal_callback=lambda _: GoalResponse.ACCEPT,
                                       cancel_callback=lambda _: CancelResponse.ACCEPT,
                                       callback_group=self.cb)
        self.spin_server = ActionServer(self, Spin, "spin", self.exec_spin,
                                        goal_callback=lambda _: GoalResponse.ACCEPT,
                                        cancel_callback=lambda _: CancelResponse.ACCEPT,
                                        callback_group=self.cb)
        self.get_logger().info("raisin_nav_glue up: goals -> /planning/set_waypoints (waypoint frame: %s, pose from %s)"
                               % (self.waypoint_frame, g("odom_topic")))

    # ------------------------------------------------------------------ helpers
    def _static(self, parent, child, xyz, rpy):
        t = TransformStamped()
        t.header.stamp = self.get_clock().now().to_msg()
        t.header.frame_id, t.child_frame_id = parent, child
        t.transform.translation.x, t.transform.translation.y, t.transform.translation.z = map(float, xyz)
        r, p, y = rpy
        cr, sr, cp, sp, cy, sy = math.cos(r / 2), math.sin(r / 2), math.cos(p / 2), math.sin(p / 2), math.cos(y / 2), math.sin(y / 2)
        t.transform.rotation.w = cr * cp * cy + sr * sp * sy
        t.transform.rotation.x = sr * cp * cy - cr * sp * sy
        t.transform.rotation.y = cr * sp * cy + sr * cp * sy
        t.transform.rotation.z = cr * cp * sy - sr * sp * cy
        return t

    def on_odom(self, msg):
        with self.lock:
            self.odom = msg
            self.pose_frame = msg.header.frame_id
        t = TransformStamped()
        t.header.stamp = msg.header.stamp
        t.header.frame_id, t.child_frame_id = self.odom_frame, self.base_frame
        t.transform.translation.x = msg.pose.pose.position.x
        t.transform.translation.y = msg.pose.pose.position.y
        t.transform.translation.z = msg.pose.pose.position.z
        t.transform.rotation = msg.pose.pose.orientation
        self.tf.sendTransform(t)
        out = Odometry()
        out.header.stamp = msg.header.stamp
        out.header.frame_id, out.child_frame_id = self.odom_frame, self.base_frame
        out.pose, out.twist = msg.pose, msg.twist
        self.odom_pub.publish(out)

    def on_image(self, key, msg):
        info = self.cam_info[key]
        info.header.stamp = msg.header.stamp
        self.cam_info_pub[key].publish(info)

    def on_cloud(self, msg):
        pose = self.robot_pose3()
        if pose is None or msg.width == 0:
            return
        step = msg.point_step
        buf = np.frombuffer(bytes(msg.data), dtype=np.uint8).reshape(-1, step)
        offs = {f.name: f.offset for f in msg.fields}
        if not all(k in offs for k in ("x", "y", "z")):
            return
        xyz = np.stack([buf[:, offs[k]:offs[k] + 4].copy().view(np.float32).reshape(-1) for k in ("x", "y", "z")], axis=1)
        rx, ry, rz = pose
        rel = xyz - np.array([rx, ry, rz], dtype=np.float32)
        band = (rel[:, 2] > -0.25) & (rel[:, 2] < 1.4)         # wall height: above the floor, below the ceiling
        rel = rel[band]
        if len(rel) < 30:
            return
        r = np.hypot(rel[:, 0], rel[:, 1])
        near = r > 0.35
        rel, r = rel[near], r[near]
        az = np.arctan2(rel[:, 1], rel[:, 0])
        b = ((az + math.pi) / (2 * math.pi) * self.n_bins).astype(np.int64) % self.n_bins
        rmin = np.full(self.n_bins, np.inf, dtype=np.float32)
        np.minimum.at(rmin, b, r)
        res = self.costmap_res
        # free space: along each azimuth up to (nearest hit - 1 cell), or 6 m when nothing was hit
        ang = (np.arange(self.n_bins) + 0.5) / self.n_bins * 2 * math.pi - math.pi
        reach = np.where(np.isfinite(rmin), rmin - 1.5 * res, 0.0).clip(0.0, 14.0)   # bins without a hit are not cleared
        ks = np.arange(0.0, 14.0, res * 0.7, dtype=np.float32)
        ok = ks[None, :] <= reach[:, None]
        fx = rx + np.cos(ang)[:, None] * ks[None, :]
        fy = ry + np.sin(ang)[:, None] * ks[None, :]
        ix = np.floor((fx[ok] - self.map_x0) / res).astype(np.int64)
        iy = np.floor((fy[ok] - self.map_y0) / res).astype(np.int64)
        inside = (ix >= 0) & (ix < self.map_w) & (iy >= 0) & (iy < self.map_h)
        free_idx = np.unique(iy[inside] * self.map_w + ix[inside])
        hx = np.floor((rx + rel[:, 0] - self.map_x0) / res).astype(np.int64)
        hy = np.floor((ry + rel[:, 1] - self.map_y0) / res).astype(np.int64)
        hin = (hx >= 0) & (hx < self.map_w) & (hy >= 0) & (hy < self.map_h)
        hit_idx = np.unique(hy[hin] * self.map_w + hx[hin])
        with self.map_lock:
            flat = self.logodds.reshape(-1)
            flat[free_idx] = np.maximum(flat[free_idx] - 0.35, -4.0)
            flat[hit_idx] = np.minimum(flat[hit_idx] + 0.9, 4.0)
            self.map_scans += 1

    def publish_map(self):
        pose = self.robot_pose()
        if pose is None or self.map_scans == 0:
            return
        res = self.costmap_res
        with self.map_lock:
            lo = self.logodds
            rows = np.flatnonzero((np.abs(lo) > 0.05).any(axis=1))
            cols = np.flatnonzero((np.abs(lo) > 0.05).any(axis=0))
            if len(rows) == 0:
                return
            r0, r1 = max(rows[0] - 5, 0), min(rows[-1] + 6, self.map_h)
            c0, c1 = max(cols[0] - 5, 0), min(cols[-1] + 6, self.map_w)
            sub = lo[r0:r1, c0:c1]
            data = np.full(sub.shape, -1, dtype=np.int8)
            data[sub <= -0.4] = 0
            data[sub >= 0.85] = 100
        out = OccupancyGrid()
        out.header.stamp = self.get_clock().now().to_msg()
        out.header.frame_id = self.map_frame
        out.info.resolution = res
        out.info.width, out.info.height = int(c1 - c0), int(r1 - r0)
        out.info.origin.position.x = float(self.map_x0 + c0 * res)
        out.info.origin.position.y = float(self.map_y0 + r0 * res)
        out.info.origin.orientation.w = 1.0
        out.data = data.reshape(-1).tolist()
        self.costmap_pub.publish(out)

    def robot_pose3(self):
        with self.lock:
            o = self.odom
        if o is None:
            return None
        return o.pose.pose.position.x, o.pose.pose.position.y, o.pose.pose.position.z

    def on_goal_pose(self, msg, use_yaw=False):
        q = msg.pose.orientation
        wp = Waypoint(frame=self.wp_frame(), x=float(msg.pose.position.x), y=float(msg.pose.position.y), z=0.0,
                      use_z=False, yaw=float(yaw_of(q)), use_yaw=bool(use_yaw))
        threading.Thread(target=self.send_waypoints, args=([wp],), daemon=True).start()

    def on_status(self, msg):
        with self.lock:
            self.status = msg

    def robot_pose(self):
        with self.lock:
            o = self.odom
        if o is None:
            return None
        return o.pose.pose.position.x, o.pose.pose.position.y, yaw_of(o.pose.pose.orientation)

    def wp_frame(self):
        if self.waypoint_frame != "auto":
            return self.waypoint_frame
        with self.lock:
            return self.pose_frame or "odom"

    def send_waypoints(self, wps):
        for wp in wps:
            wp.frame = self.wp_frame()
        if not self.set_wp.wait_for_service(timeout_sec=5.0):
            self.get_logger().error("/planning/set_waypoints not available (is raisin_bridge connected and navigation loaded?)")
            return False
        req = SetWaypoints.Request()
        req.waypoints = wps
        req.repetition = 1
        req.current_index = 0
        req.infinite_loop = False
        fut = self.set_wp.call_async(req)
        deadline = time.time() + 5.0
        while not fut.done() and time.time() < deadline:
            time.sleep(0.05)
        if not fut.done() or fut.result() is None or not fut.result().success:
            self.get_logger().error("set_waypoints failed: %s" % (fut.result().message if fut.done() and fut.result() else "timeout"))
            return False
        return True

    def wait_until_reached(self, goal_handle, target, feedback_fn):
        """Block until raisin reports no active goal and the robot is within tolerance, or cancel/timeout."""
        x, y, yaw = target
        t0 = time.time()
        seen_active = False
        while rclpy.ok():
            if goal_handle.is_cancel_requested:
                self.send_waypoints([])
                return None  # canceled; the caller finalizes the goal handle
            pose = self.robot_pose()
            with self.lock:
                st = self.status
            if pose is not None:
                d = math.hypot(x - pose[0], y - pose[1])
                dyaw = abs(wrap(yaw - pose[2])) if yaw is not None else 0.0
                feedback_fn(pose, d)
                active = bool(st.has_goal) if st is not None else None
                seen_active = seen_active or bool(active)
                if d < self.goal_tol and dyaw < self.yaw_tol and (active is False or active is None):
                    return True
                if seen_active and active is False and d < 3 * self.goal_tol:
                    return True  # raisin declared arrival slightly outside our tolerance
            if time.time() - t0 > self.goal_timeout:
                self.get_logger().warn("goal timed out")
                return False
            time.sleep(0.1)
        return False

    # ------------------------------------------------------------------ actions
    def exec_navigate(self, goal_handle):
        pose = goal_handle.request.pose.pose
        x, y, yaw = pose.position.x, pose.position.y, yaw_of(pose.orientation)
        use_yaw = abs(pose.orientation.w) < 0.9999 or abs(pose.orientation.z) > 1e-4
        self.get_logger().info("navigate_to_pose -> (%.2f, %.2f, yaw %.2f)" % (x, y, yaw))
        wp = Waypoint(frame=self.wp_frame(), x=float(x), y=float(y), z=0.0, use_z=False,
                      yaw=float(yaw), use_yaw=bool(use_yaw))
        result = NavigateToPose.Result()
        if not self.send_waypoints([wp]):
            goal_handle.abort()
            return result
        fb = NavigateToPose.Feedback()
        t0 = self.get_clock().now()

        def feedback(pose_now, dist):
            fb.current_pose.header.frame_id = self.map_frame
            fb.current_pose.pose.position.x, fb.current_pose.pose.position.y = pose_now[0], pose_now[1]
            fb.distance_remaining = float(dist)
            fb.navigation_time = (self.get_clock().now() - t0).to_msg()
            goal_handle.publish_feedback(fb)

        ok = self.wait_until_reached(goal_handle, (x, y, yaw if use_yaw else None), feedback)
        if ok is None:
            goal_handle.canceled()
        elif ok:
            goal_handle.succeed()
        else:
            goal_handle.abort()
        return result

    def exec_spin(self, goal_handle):
        result = Spin.Result()
        pose = self.robot_pose()
        if pose is None:
            self.get_logger().error("spin requested before any odometry arrived")
            goal_handle.abort()
            return result
        # raisin navigation aligns heading when a waypoint carries use_yaw (planner goal heading +
        # MPPI GoalAngleCritic) and, with yaw_goal_tolerance < pi, only reports arrival once aligned.
        # A full turn is split into legs so every yaw target is unambiguous.
        total = float(goal_handle.request.target_yaw)
        legs = max(1, min(self.spin_legs, int(math.ceil(abs(total) / (2.0 * math.pi / 3.0)))))
        step = total / legs
        self.get_logger().info("spin %.2f rad as %d yaw waypoint(s)" % (total, legs))
        fb = Spin.Feedback()
        traveled = 0.0
        for i in range(legs):
            target_yaw = wrap(pose[2] + step * (i + 1))
            wp = Waypoint(frame=self.wp_frame(), x=float(pose[0]), y=float(pose[1]), z=0.0, use_z=False,
                          yaw=float(target_yaw), use_yaw=True)
            if not self.send_waypoints([wp]):
                goal_handle.abort()
                return result

            def feedback(pose_now, _dist, _base=traveled):
                fb.angular_distance_traveled = float(_base + abs(wrap(pose_now[2] - pose[2])))
                goal_handle.publish_feedback(fb)

            ok = self.wait_until_reached(goal_handle, (pose[0], pose[1], target_yaw), feedback)
            if ok is None:
                goal_handle.canceled()
                return result
            if not ok:
                goal_handle.abort()
                return result
            traveled += abs(step)
        goal_handle.succeed()
        return result


def main():
    rclpy.init()
    node = RaisinNavGlue()
    ex = MultiThreadedExecutor(num_threads=4)
    ex.add_node(node)
    try:
        ex.spin()
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == "__main__":
    main()
