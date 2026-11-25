#!/usr/bin/env python3
"""Crop the FAST-LIO cloud to the band and wedge the costmap should see, and
re-express it relative to the rig's own height.

Two constraints, and no off-the-shelf node does both:

  height   z in [min_z, max_z] measured in the BODY frame, i.e. relative to the
           lidar itself. VoxelLayer's own height limits are map-frame, which is
           the wrong frame on a rig that walks down 3.6 m of building -- a band
           fixed in the map stops matching the lidar the moment the carrier
           changes floor, and the walls silently stop being marked.

  bearing  |atan2(y, x)| <= half_fov. pcl_ros's CropBox is an axis-aligned box
           and cannot express a wedge, but the restriction matters: landmarks
           only come from the D455, so ground the camera never sees is ground
           whose frontiers can never be resolved.

/cloud_registered_body is already published in `body`, so both tests are plain
arithmetic on the points as they arrive.

The third job is what makes the costmap survive FAST-LIO. Its z estimate drifts
badly on this rig -- 3.6 m over one four-minute walk down a corridor whose real
height never changed -- and a voxel grid whose z window is fixed in the map
frame simply loses the slice when that happens: the walls stop being marked and
the map quietly goes blank.

Following the rig by moving VoxelLayer's origin_z is not an option, because
nav2_voxel_grid has no way to shift a column in z. The marked bits are a
bitmask indexed by voxel number, so moving the origin silently reinterprets
every bit already set as being at a different height.

So the points are moved instead. Output is published in `body_level`: the rig's
x and y, world axes, and z measured FROM THE LIDAR rather than from wherever
FAST-LIO believes the floor is. The voxel window can then be a tight band about
zero and can never drift out of it.
"""

import math

import numpy as np
import rclpy
import rclpy.duration
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from geometry_msgs.msg import TransformStamped
from sensor_msgs.msg import PointCloud2
from sensor_msgs_py import point_cloud2
from tf2_ros import Buffer, TransformListener, TransformBroadcaster


def _quat_to_matrix(x, y, z, w):
    """Rotation matrix from a quaternion, without pulling in scipy."""
    n = math.sqrt(x * x + y * y + z * z + w * w)
    if n == 0.0:
        return np.eye(3)
    x, y, z, w = x / n, y / n, z / n, w / n
    return np.array([
        [1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)],
        [2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)],
        [2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)],
    ])


class CloudSlice(Node):
    def __init__(self):
        super().__init__('cloud_slice')
        self.declare_parameter('min_z', -0.5)
        self.declare_parameter('max_z', 0.5)
        self.declare_parameter('half_fov_deg', 43.5)
        self.declare_parameter('min_range', 0.5)
        # Beyond this a point contributes nothing: the costmap's own
        # obstacle_max_range and raytrace_max_range are both 3 m. Keeping the
        # reach short also keeps the tilt spread small -- a point at range R
        # with the rig pitched by t lands R*sin(t) away in world z, which is
        # what the voxel window has to be wide enough to hold.
        self.declare_parameter('max_range', 4.0)
        self.declare_parameter('map_frame', 'map')
        self.declare_parameter('body_frame', 'body')
        self.declare_parameter('level_frame', 'body_level')

        self.buf = Buffer()
        TransformListener(self.buf, self)
        self.tf_pub = TransformBroadcaster(self)

        self.pub = self.create_publisher(PointCloud2, 'cloud_out',
                                         qos_profile_sensor_data)
        self.create_subscription(PointCloud2, 'cloud_in', self.on_cloud,
                                 qos_profile_sensor_data)
        # FAST-LIO's /Odometry carries the lidar pose stamped with the SCAN
        # time -- the one thing TF cannot give us here. Its TF broadcast is the
        # same pose but arrives ~2-3 s late on the bag clock, so a lookup at
        # the scan stamp is refused as "extrapolation into the future". Keep a
        # short ring of odometry and pick the entry nearest each scan.
        from nav_msgs.msg import Odometry
        self._odom = []
        self.create_subscription(Odometry, 'odom_in', self.on_odom, qos_profile_sensor_data)
        self._logged = False
        self._src = {'odom': 0, 'tf': 0}
        self.create_timer(30.0, self._report_src)

    def on_odom(self, msg):
        st = msg.header.stamp.sec + msg.header.stamp.nanosec * 1e-9
        p = msg.pose.pose.position; q = msg.pose.pose.orientation
        self._odom.append((st, (p.x, p.y, p.z), (q.x, q.y, q.z, q.w)))
        if len(self._odom) > 200:
            del self._odom[:100]

    def _pose_for(self, stamp):
        """Lidar pose at `stamp`: nearest odometry, else the latest TF."""
        want = stamp.sec + stamp.nanosec * 1e-9
        if self._odom:
            st, t, q = min(self._odom, key=lambda e: abs(e[0] - want))
            if abs(st - want) < 0.15:
                self._src['odom'] += 1
                return t, q
        self._src['tf'] += 1
        try:
            tf = self.buf.lookup_transform(self._p('map_frame'), self._p('body_frame'),
                                           rclpy.time.Time())
        except Exception:
            return None
        t = tf.transform.translation; q = tf.transform.rotation
        return (t.x, t.y, t.z), (q.x, q.y, q.z, q.w)

    def _report_src(self):
        o, t = self._src['odom'], self._src['tf']
        if o + t:
            self.get_logger().info(f'pose source: odom {o}, tf-fallback {t}')

    def _p(self, name):
        return self.get_parameter(name).value

    def on_cloud(self, msg: PointCloud2):
        """Filter FAST-LIO's world-frame cloud around the lidar's current pose.

        Input is /cloud_registered: FAST-LIO has already put every point into
        camera_init using the pose it estimated FOR THAT SCAN. This node used to
        take the body-frame cloud and rotate it with the latest TF instead --
        but that TF is published after the scan is processed, so it lags the
        scan by a frame or more, and while walking each scan landed a few cm to
        tens of cm off. Summed over a corridor that is the costmap "drift" seen
        against a FAST-LIO trajectory that itself did not drift.

        The lidar pose at scan time is still needed -- for the FOV wedge, the
        height band and the sensor origin the voxel map raytraces from -- so it
        is looked up AT THE SCAN STAMP, not "latest".
        """
        dtype = point_cloud2.dtype_from_fields(msg.fields, msg.point_step)
        n_pts = msg.width * msg.height
        if n_pts == 0:
            return
        pts = np.frombuffer(bytes(msg.data), dtype=dtype, count=n_pts)

        pose = self._pose_for(msg.header.stamp)
        if pose is None:
            self.get_logger().warn('no lidar pose yet', throttle_duration_sec=5.0)
            return
        t, q = pose
        rot = _quat_to_matrix(q[0], q[1], q[2], q[3])

        # Points relative to the lidar at scan time, in world axes.
        x = pts['x'].astype(np.float64) - t[0]
        y = pts['y'].astype(np.float64) - t[1]
        z = pts['z'].astype(np.float64) - t[2]

        # Bearing is camera-relative: heading of each point in the lidar's own
        # yaw frame. Only yaw matters for the wedge.
        yaw = math.atan2(rot[1, 0], rot[0, 0])
        half = math.radians(float(self._p('half_fov_deg')))
        rel = np.arctan2(y, x) - yaw
        rel = (rel + np.pi) % (2 * np.pi) - np.pi
        rng = np.hypot(x, y)
        far_limit = float(self._p('max_range'))
        with np.errstate(invalid='ignore'):
            keep = (np.isfinite(x) & np.isfinite(y) & np.isfinite(z) &
                    (np.abs(rel) <= half) & (rng >= self._p('min_range')) &
                    (z >= self._p('min_z')) & (z <= self._p('max_z')))
            if far_limit > 0.0:
                keep &= rng <= far_limit

        kept = pts[keep].copy()
        kept['x'] = x[keep]
        kept['y'] = y[keep]
        kept['z'] = z[keep]

        # body_level: the lidar's x, y at SCAN TIME, z = 0, world axes -- so a
        # point's z is its height above the lidar and z drift never reaches the
        # map. Stamped with the scan time so the consumer can look this exact
        # pose up rather than the latest one.
        tfm = TransformStamped()
        tfm.header.stamp = msg.header.stamp
        tfm.header.frame_id = self._p('map_frame')
        tfm.child_frame_id = self._p('level_frame')
        tfm.transform.translation.x = t[0]
        tfm.transform.translation.y = t[1]
        tfm.transform.translation.z = 0.0
        tfm.transform.rotation.w = 1.0
        self.tf_pub.sendTransform(tfm)

        header = msg.header
        header.frame_id = self._p('level_frame')
        out = point_cloud2.create_cloud(header, msg.fields, kept,
                                        point_step=msg.point_step)
        out.is_dense = False
        self.pub.publish(out)

        if not self._logged:
            self._logged = True
            self.get_logger().info(
                f'slicing {msg.header.frame_id} (world) about {self._p("body_frame")}: z '
                f'[{self._p("min_z")}, {self._p("max_z")}] m, bearing '
                f'+-{self._p("half_fov_deg")} deg, range '
                f'[{self._p("min_range")}, '
                f'{self._p("max_range") or "inf"}] m '
                f'-- kept {int(keep.sum())}/{keep.size} points')


def main():
    rclpy.init()
    n = CloudSlice()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
