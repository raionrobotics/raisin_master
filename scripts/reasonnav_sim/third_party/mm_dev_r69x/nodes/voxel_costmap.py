#!/usr/bin/env python3
"""A voxel map whose z window rides with the lidar, and the costmap it projects.

Written from scratch rather than configured out of nav2's VoxelLayer, because
the one thing this rig needs is the one thing that layer cannot do. FAST-LIO's
height estimate drifts -- 3.6 m over a four-minute walk down a corridor whose
real height never changed -- and nav2_voxel_grid stores each (x, y) column as a
bitmask indexed by absolute voxel number with no way to shift it. Moving
origin_z there silently reinterprets every bit already set as being at a
different height, so the choice is a window wide enough to swallow the drift
(and too coarse to be useful) or a map that goes blank when the drift exceeds
it.

Here the window rolls. Slab 0 always sits Z_HALF below the lidar, and when the
lidar's height moves by whole slabs every column is shifted by that many bits --
which is exactly the operation nav2 lacks, and is one vectorised shift over the
whole grid.

    z = +1.6  ─────────────  slab 15      kept for context and clearing
                  ...
    z = +0.5  ─────────────  slab 10  ┐
    lidar ────────────────   slab  8  │   any occupied voxel in this band
    z = -0.5  ─────────────  slab  5  ┘   makes the (x, y) cell LETHAL
                  ...
    z = -1.6  ─────────────  slab  0

Input is /cloud_body_slice from cloud_slice.py: already world-axis-aligned,
already cropped to the camera's wedge, and with z measured from the lidar
rather than from wherever FAST-LIO believes the floor is.

Output is a plain OccupancyGrid. nav2 consumes it through a StaticLayer and
keeps doing what it is good at -- inflation, and the costmap service the rest
of the stack waits on -- while the occupancy decision lives here.
"""

import math

import numpy as np
import rclpy
import rclpy.duration
from rclpy.node import Node
from rclpy.qos import QoSDurabilityPolicy, QoSProfile, QoSReliabilityPolicy
from rclpy.qos import qos_profile_sensor_data
from nav_msgs.msg import OccupancyGrid
from sensor_msgs.msg import PointCloud2
from sensor_msgs_py import point_cloud2
from tf2_ros import Buffer, TransformListener

FREE = 0
LETHAL = 100
UNKNOWN = -1


class VoxelCostmap(Node):
    def __init__(self):
        super().__init__('voxel_costmap')
        p = self.declare_parameter
        p('resolution', 0.10)          # xy cell size, metres
        p('width', 240.0)              # metres
        p('height', 240.0)
        p('origin_x', -120.0)
        p('origin_y', -120.0)
        p('z_resolution', 0.2)
        p('z_half_window', 1.6)        # kept above and below the lidar
        p('lethal_half_band', 0.5)     # decides LETHAL
        # Two ranges, not one. A point further away than obstacle_range must
        # still clear the space in front of it -- otherwise a corridor only
        # becomes free where something happens to be standing within 3 m, and
        # open ground ahead stays unknown forever. nav2's ObstacleLayer always
        # split these; folding them into a single max_range is what broke it.
        p('obstacle_range', 3.0)       # marked as LETHAL out to here
        p('raytrace_range', 12.0)      # cleared out to here
        p('publish_period', 0.5)
        p('map_frame', 'map')
        p('cloud_frame', 'body_level')

        self.res = float(self.get_parameter('resolution').value)
        self.zres = float(self.get_parameter('z_resolution').value)
        self.zhalf = float(self.get_parameter('z_half_window').value)
        self.nx = int(round(float(self.get_parameter('width').value) / self.res))
        self.ny = int(round(float(self.get_parameter('height').value) / self.res))
        self.ox = float(self.get_parameter('origin_x').value)
        self.oy = float(self.get_parameter('origin_y').value)
        self.nz = int(round(2.0 * self.zhalf / self.zres))
        if self.nz > 32:
            raise ValueError(f'{self.nz} slabs will not fit in a uint32 column')

        # One uint32 per (x, y): bit k set means slab k holds something. 2400^2
        # columns is 23 MB, which is the whole point of the bitmask -- a dense
        # (nz, ny, nx) array of the same extent would be 184 MB.
        self.marked = np.zeros((self.ny, self.nx), dtype=np.uint32)
        # Whether a column has ever been observed, so unobserved ground reports
        # UNKNOWN instead of free.
        self.seen = np.zeros((self.ny, self.nx), dtype=bool)
        # World height of the bottom of slab 0. None until the first cloud.
        self.z0 = None

        self.buf = Buffer()
        TransformListener(self.buf, self)
        latched = QoSProfile(
            depth=1,
            reliability=QoSReliabilityPolicy.RELIABLE,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL)
        self.pub = self.create_publisher(OccupancyGrid, 'voxel_costmap', latched)
        self.create_subscription(PointCloud2, 'cloud_in', self.on_cloud,
                                 qos_profile_sensor_data)
        self.create_timer(float(self.get_parameter('publish_period').value),
                          self.publish_map)
        self.get_logger().info(
            f'{self.nx}x{self.ny} @ {self.res} m, {self.nz} slabs of '
            f'{self.zres} m (+-{self.zhalf} m about the lidar), lethal within '
            f'+-{self.get_parameter("lethal_half_band").value} m')

    # ------------------------------------------------------------------ z roll
    def _roll_z(self, lidar_z):
        """Slide the window so slab 0 stays z_half_window below the lidar.

        The shift is in whole slabs, so the window only moves once the lidar has
        climbed or dropped a full 0.2 m -- otherwise a millimetre of jitter
        would smear the map by shifting it back and forth every scan.
        """
        want = lidar_z - self.zhalf
        if self.z0 is None:
            self.z0 = want
            return
        k = int(round((want - self.z0) / self.zres))
        if k == 0:
            return
        if abs(k) >= self.nz:
            # Teleported (or FAST-LIO reinitialised): nothing in the old window
            # overlaps the new one.
            self.marked[:] = 0
        elif k > 0:
            # Window moved up: slab k becomes slab 0, the top k slabs are new.
            self.marked >>= np.uint32(k)
        else:
            self.marked <<= np.uint32(-k)
            self.marked &= np.uint32((1 << self.nz) - 1)
        self.z0 += k * self.zres

    # --------------------------------------------------------------- ingestion
    def on_cloud(self, msg: PointCloud2):
        frame = self.get_parameter('cloud_frame').value
        try:
            # At the cloud's own stamp. cloud_slice broadcasts body_level with
            # the scan stamp BEFORE publishing the cloud, so this exact lookup
            # always resolves -- and it must be exact: "latest" is the NEXT
            # scan's pose whenever two scans queue up, which shifts every point
            # by the distance walked in between (~10 cm/scan). That was the
            # residual smear left after switching to /cloud_registered.
            tf = self.buf.lookup_transform(
                self.get_parameter('map_frame').value, frame, msg.header.stamp,
                timeout=rclpy.duration.Duration(seconds=0.05))
        except Exception as e:
            self.get_logger().warn(f'no map <- {frame}: {e}', once=True)
            return
        sx = tf.transform.translation.x
        sy = tf.transform.translation.y
        # cloud_slice publishes body_level at z = 0 by construction, so the
        # lidar sits at slab index nz/2 whatever its true height is doing.
        self._roll_z(0.0)

        dtype = point_cloud2.dtype_from_fields(msg.fields, msg.point_step)
        n = msg.width * msg.height
        if n == 0:
            return
        pts = np.frombuffer(bytes(msg.data), dtype=dtype, count=n)
        px = pts['x'].astype(np.float64)
        py = pts['y'].astype(np.float64)
        pz = pts['z'].astype(np.float64)
        ok = np.isfinite(px) & np.isfinite(py) & np.isfinite(pz)
        px, py, pz = px[ok], py[ok], pz[ok]
        if px.size == 0:
            return

        rng = np.hypot(px, py)
        obs_r = float(self.get_parameter('obstacle_range').value)
        ray_r = float(self.get_parameter('raytrace_range').value)

        # Everything within raytrace_range clears; the ray is cut short at
        # raytrace_range for points beyond it, so a distant return still frees
        # the ground it flew over.
        # Points beyond raytrace_range are not discarded, they are pulled back
        # onto the ray at raytrace_range: the ground they flew over is still
        # observed free even though the return itself is too far to trust.
        far = rng > ray_r
        if far.any():
            k = ray_r / np.maximum(rng[far], 1e-6)
            px[far] *= k
            py[far] *= k
            pz[far] *= k
            rng[far] = ray_r
        cx, cy, cz, crng = px, py, pz, rng
        if cx.size == 0:
            return

        # --- clear along each ray, then mark the endpoints -------------------
        # Order matters: a ray that grazes past one obstacle must not erase the
        # hit that another ray recorded in the same voxel this scan.
        self._clear_rays(sx, sy, cx, cy, cz, crng)

        # Only the near, genuine returns become obstacles -- a point that was
        # pulled back to raytrace_range is not a hit, it is the end of a
        # clearing ray.
        mark = (crng <= obs_r) & (~far)
        if mark.any():
            self._mark(sx, sy, cx[mark], cy[mark], cz[mark])

    def _cells(self, wx, wy):
        ix = np.floor((wx - self.ox) / self.res).astype(np.int64)
        iy = np.floor((wy - self.oy) / self.res).astype(np.int64)
        inside = (ix >= 0) & (ix < self.nx) & (iy >= 0) & (iy < self.ny)
        return ix, iy, inside

    def _slabs(self, z):
        return np.floor((z - self.z0) / self.zres).astype(np.int64)

    def _mark(self, sx, sy, px, py, pz):
        ix, iy, inside = self._cells(sx + px, sy + py)
        iz = self._slabs(pz)
        good = inside & (iz >= 0) & (iz < self.nz)
        if not good.any():
            return
        ix, iy, iz = ix[good], iy[good], iz[good]
        bits = (np.uint32(1) << iz.astype(np.uint32))
        # np.bitwise_or.at, not |=, so several points landing in one column all
        # contribute instead of the last write winning.
        np.bitwise_or.at(self.marked, (iy, ix), bits)
        self.seen[iy, ix] = True

    def _clear_rays(self, sx, sy, px, py, pz, rng):
        """Walk every ray from the sensor and empty the voxels it passes.

        Sampled at half a cell rather than a true 3D Bresenham: the rays are at
        most max_range long, so the oversampling costs a few hundred thousand
        integer ops a scan and cannot skip a cell.
        """
        step = self.res * 0.5
        n_steps = int(math.ceil(float(rng.max()) / step)) + 1
        if n_steps <= 1:
            return
        # Fractions along each ray, clipped short of the endpoint so the hit
        # itself is never cleared.
        t = np.linspace(0.0, 1.0, n_steps, dtype=np.float64)[None, :]
        keep = (t * rng[:, None]) < (rng[:, None] - self.res)

        xs = sx + px[:, None] * t
        ys = sy + py[:, None] * t
        zs = pz[:, None] * t

        ix, iy, inside = self._cells(xs[keep], ys[keep])
        iz = self._slabs(zs[keep])
        good = inside & (iz >= 0) & (iz < self.nz)
        if not good.any():
            return
        ix, iy, iz = ix[good], iy[good], iz[good]
        clear = ~(np.uint32(1) << iz.astype(np.uint32))
        np.bitwise_and.at(self.marked, (iy, ix), clear)
        self.seen[iy, ix] = True

    # ---------------------------------------------------------------- publish
    def publish_map(self):
        if self.z0 is None:
            return
        band = float(self.get_parameter('lethal_half_band').value)
        # Slabs overlapping [lidar - band, lidar + band). The lidar sits at
        # z = 0 in this frame, and slab 0 starts at self.z0 (= -z_half_window).
        lo = max(0, int(math.floor((-band - self.z0) / self.zres)))
        hi = min(self.nz, int(math.ceil((band - self.z0) / self.zres)))
        if hi <= lo:
            return
        band_mask = np.uint32(((1 << hi) - 1) ^ ((1 << lo) - 1))

        grid = np.full((self.ny, self.nx), UNKNOWN, dtype=np.int8)
        grid[self.seen] = FREE
        grid[(self.marked & band_mask) != 0] = LETHAL

        msg = OccupancyGrid()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = self.get_parameter('map_frame').value
        msg.info.resolution = self.res
        msg.info.width = self.nx
        msg.info.height = self.ny
        msg.info.origin.position.x = self.ox
        msg.info.origin.position.y = self.oy
        msg.info.origin.orientation.w = 1.0
        msg.data = grid.reshape(-1).tolist()
        self.pub.publish(msg)


def main():
    rclpy.init()
    n = VoxelCostmap()
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
