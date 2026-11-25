import math
import math
import os
#!/usr/bin/env python3
"""Landmark behavior handlers for VLM navigation system."""

import time
import numpy as np
from geometry_msgs.msg import Pose
from std_msgs.msg import String, Float32MultiArray
from mm_dev.common.tf_utils import pose_msg_to_xyyaw, yaw_to_quaternion
from mm_dev.common.vis_utils import xyyaw_to_marker
from geometry_msgs.msg import TransformStamped
from tf2_geometry_msgs import do_transform_pose
from mm_dev.common.nav_utils import goToPose, spin_wait, note_visited
from mm_dev.common.camera_utils import pan_to_target, relative_pan
from mm_dev.common.geometry_utils import get_cardinal_direction, update_sign_directions
import rclpy


# Where a person can stand to look at a door/sign. OccupancyGrid scale (0..100
# with nav2's inflation folded in): below this is standable, 100 is a wall.
APPROACH_MAX_COST = int(os.environ.get('REASONNAV_APPROACH_MAX_COST', '60'))
# Total time spent at a door whose plate was not already read on the way.
DOOR_INSPECT_S = float(os.environ.get('REASONNAV_DOOR_INSPECT_S', '6.0'))
# Blocking plate inspection at the door. Off by default: the passive reader does it.
DOOR_INSPECT = os.environ.get('REASONNAV_DOOR_INSPECT', '0') == '1'
APPROACH_STAND_M = float(os.environ.get('REASONNAV_APPROACH_STAND_M', '1.5'))
APPROACH_SEARCH_M = float(os.environ.get('REASONNAV_APPROACH_SEARCH_M', '3.5'))

class LandmarkHandlers:
    """Handle different landmark types (door, sign, person, frontier)."""

    def __init__(self, node):
        """Initialize landmark handlers.

        Args:
            node: VLMNav node instance with all necessary attributes
        """
        self.node = node
        # Doors whose plate was seen but not readable from the 1.5 m stand
        # point: one closer try (0.8 m) before they count as visited.
        self._door_retry = set()

    def handle_door_landmark(self, navigator, next_landmark, landmark_pose, max_attempts, vlm_sign_dir):
        """Handle door landmark: approach, detect room label, and OCR.

        Args:
            navigator: BasicNavigator instance
            next_landmark: Landmark dictionary with 'name' key
            landmark_pose: Initial landmark pose (can be None)
            max_attempts: Maximum repositioning attempts
            vlm_sign_dir: Use VLM for sign direction conversion

        Returns:
            bool: True if target door found, False otherwise
        """
        if 'a room label' in self.node.landmark_db.landmark_db:
            del self.node.landmark_db.landmark_db['a room label']
        # A second "door" within 2.5 m of one whose number is already read is
        # the same door seen again (detections wander a metre or more). Walking
        # up to it, failing to read a plate that is not there, and coming back
        # once more is what looked like staring at walls.
        try:
            didx = int(next_landmark['name'].split('_')[-1])
            ddb = self.node.landmark_db.landmark_db['a door']
            dp = ddb['positions'][didx]
            for j, lab in enumerate(ddb.get('labels', [])):
                if j != didx and lab and math.hypot(ddb['positions'][j][0] - dp[0], ddb['positions'][j][1] - dp[1]) < 2.5:
                    self.node.get_logger().info(
                        f"{next_landmark['name']} is {math.hypot(ddb['positions'][j][0] - dp[0], ddb['positions'][j][1] - dp[1]):.1f} m from door {j} ({lab}) -- same door, dropping it")
                    self.node.landmark_db.mark_useless('a door', didx)
                    return False
        except Exception:
            pass

        door_number = None
        attempts = 0
        approach_dist = -1.5   # 2 m put the plate at ~50 px in dark frames and OCR gave up; 1.5 m is ~65 px
        try:
            if int(next_landmark['name'].split('_')[-1]) in self._door_retry:
                approach_dist = -0.8   # second visit: the plate was there but 25 px was not enough
        except ValueError:
            pass

        while attempts <= max_attempts and door_number is None:
            landmark_pose, approach_pose = self.get_landmark_approach_pose(next_landmark['name'], approach_dist)
            approach_x, approach_y, approach_yaw = pose_msg_to_xyyaw(approach_pose)
            approach_marker = xyyaw_to_marker(rclpy.time.Time(), "Approach", approach_x, approach_y, approach_yaw,
                                          rgb=(0.0, 1.0, 0.0), scale=(1.2, 0.25, 0.25))
            self.node.goal_marker_pub.publish(approach_marker)

            nav_result = goToPose(navigator, approach_pose)

            if getattr(self.node, 'goal_reached', False):

                return True   # read in passing while walking; nothing left to inspect
            if nav_result == False:
                # On a handheld rig a False here means the carrier did not walk
                # to this door within the timeout, so retrying the identical
                # approach pose would just sit there again. Stop asking and let
                # the chooser pick something else.
                self.node.get_logger().info(
                    f"{next_landmark['name']} not reached; leaving it unread.")
                break

            pan_to_target(self.node, landmark_pose)

            # Already read while walking up? Then there is nothing to inspect.
            try:
                known = self.node.landmark_db.landmark_db['a door']['labels'][int(next_landmark['name'].split('_')[-1])]
            except Exception:
                known = None
            if known:
                door_number = known
            elif DOOR_INSPECT:
                door_number = self._detect_and_read_room_label(landmark_pose)
            else:
                # No blocking inspection. But if a plate near this door is
                # already in the background reader's queue, give it a few
                # seconds -- the carrier is standing right in front of it, which
                # is the best look the reader will ever get. Then move on either
                # way; a later read still attaches to this door.
                door_idx_ = int(next_landmark['name'].split('_')[-1])
                dpos = self.node.landmark_db.landmark_db['a door']['positions'][door_idx_]
                t_end = time.monotonic() + DOOR_INSPECT_S
                waited = False
                while time.monotonic() < t_end:
                    with self.node.room_lock:
                        pending = any(
                            v.get('read') is None and v.get('tries', 0) < 5
                            and math.hypot(v['pose'][0] - dpos[0], v['pose'][1] - dpos[1]) < 3.0
                            for v in self.node.room_labels.values())
                    known = self.node.landmark_db.landmark_db['a door']['labels'][door_idx_]
                    if known:
                        door_number = known
                        break
                    if not pending:
                        break
                    waited = True
                    time.sleep(0.5)
                if door_number is None:
                    self.node.get_logger().info(
                        f"{next_landmark['name']}: plate not read{' after waiting' if waited else ''} -- moving on; the background reader keeps trying")
                break
            attempts += 1
            relative_pan(self.node, 'center')

        self._reset_detection_to_default()
        relative_pan(self.node, 'center')

        # The trailing number in the name is the array index, which is all
        # mark_visited needs; the room number, if we got one, is stored beside
        # it rather than in its place.
        door_idx = int(next_landmark['name'].split('_')[-1])

        if door_number is not None:
            self.node.get_logger().info(f"Saw room {door_number}")
            relative_pan(self.node, 'center')
            self.node.landmark_db.mark_visited("a door", door_idx, label=door_number)
            if self._is_goal(door_number):
                pos = self.node.landmark_db.landmark_db['a door']['positions'][door_idx]
                self.node.announce_found(door_number, (pos[0], pos[1]))
                return True
        else:
            # Nothing legible. Two different situations hide behind that:
            #  - no room-label detection at all while standing in front of the
            #    door: there IS no plate (service door, glass partition, false
            #    positive). That door can never help find the target -- mark it
            #    useless so it leaves the VLM's list for good.
            #  - a plate was detected but the OCR came back -1/-2: it exists,
            #    we just could not read it this time. Visited, keep it listed.
            saw_plate = 'a room label' in self.node.landmark_db.landmark_db and \
                len(self.node.landmark_db.landmark_db['a room label']['positions']) > 0
            # A plate was seen near this door but never read: from 2.5 m a
            # 25 px plate came back "unreadable" at 0.9 confidence, the door was
            # marked visited, and the VLM kept asking for it -- the target's
            # own door, as it turned out. Leave it unvisited once and stand
            # closer next time.
            try:
                dpos = self.node.landmark_db.landmark_db['a door']['positions'][door_idx]
                with self.node.room_lock:
                    plate_unread = any(
                        v.get('read') is None and v.get('unreadable_hi', 0) < 2
                        and math.hypot(v['pose'][0] - dpos[0], v['pose'][1] - dpos[1]) < 3.0
                        for v in self.node.room_labels.values())
            except Exception:
                plate_unread = False
            if plate_unread and door_idx not in self._door_retry:
                self._door_retry.add(door_idx)
                self.node.get_logger().info(
                    f"{next_landmark['name']}: plate seen but unreadable from here -- keeping it unvisited for one closer look")
                return False
            if saw_plate or not DOOR_INSPECT:
                # Visited but unread; a later passive read still attaches to it.
                self.node.landmark_db.mark_visited("a door", door_idx)
            else:
                self.node.get_logger().info(
                    f"{next_landmark['name']}: no room label on it -- dropping it.")
                self.node.landmark_db.mark_useless("a door", door_idx)

        return False

    def _is_goal(self, door_number):
        """Compare a reading against the goal without assuming either is an int.

        Room numbers in this building carry a letter prefix (T106, T109), so
        both sides are compared as normalised strings.
        """
        goal = self.node.goal
        if goal is None:
            return False
        norm = lambda v: str(v).strip().upper().replace(' ', '')
        return norm(door_number) == norm(goal)

    def _detect_and_read_room_label(self, landmark_pose):
        """Detect room label and perform OCR."""
        room_label_query = String()
        room_label_query.data = "a room label"
        self.node.det_query_pub.publish(room_label_query)
        room_label_thresh = Float32MultiArray()
        room_label_thresh.data = [0.04]
        self.node.det_thresh_pub.publish(room_label_thresh)

        # Short. Plates are normally read on the walk up (passive OCR); this
        # is the fallback for a plate that only comes into view when standing
        # square in front of the door. 18 s of pan-and-wait was for a robot
        # with a pan-tilt head; the handheld rig has the carrier's eyes.
        time.sleep(DOOR_INSPECT_S * 0.4)
        t = 0
        while 'a room label' not in self.node.landmark_db.landmark_db and t < 1:
            if t == 0:
                pan_to_target(self.node, landmark_pose)
            if t == 1:
                relative_pan(self.node, "diag_left")
            if t == 2:
                # relative_pan is a camera_utils function, not a node method;
                # the lines above and below call it correctly.
                relative_pan(self.node, "center")
                time.sleep(1.0)
                relative_pan(self.node, "diag_right")
            t += 1
            time.sleep(4.0)
        time.sleep(4.0)

        if 'a room label' not in self.node.landmark_db.landmark_db:
            self.node.get_logger().info("No room label detected")
            return None

        label_pos = np.array(self.node.landmark_db.landmark_db['a room label']['positions'])
        label_orientation = np.array(self.node.landmark_db.landmark_db['a room label']['orientations'])
        label_pose = Pose()
        label_pose.position.x = label_pos[-1][0]
        label_pose.position.y = label_pos[-1][1]
        label_pose.position.z = label_pos[-1][2]
        label_pose.orientation.x = label_orientation[-1][0]
        label_pose.orientation.y = label_orientation[-1][1]
        label_pose.orientation.z = label_orientation[-1][2]
        label_pose.orientation.w = label_orientation[-1][3]

        # Every other call site passes the node first; this one dropped it and
        # took down vlm_nav as soon as a door reached the room-label step.
        pan_to_target(self.node, label_pose)
        time.sleep(2.0)

        self.node.get_logger().info("VLM OCR")
        door_number, confidence = self.node.vlm_read_door_cur_image()
        self.node.get_logger().info(f"OCR Reading: {door_number}, Confidence: {confidence}")

        return door_number

    def _reset_detection_to_default(self):
        """Reset detection query and threshold to default values."""
        default_query = String()
        default_query.data = self.node.default_det_query
        default_thresh = Float32MultiArray()
        default_thresh.data = self.node.default_det_thresh
        self.node.det_query_pub.publish(default_query)
        self.node.det_thresh_pub.publish(default_thresh)

    def handle_frontier_landmark(self, navigator, next_landmark, frontier_dict):
        """Handle frontier landmark: approach and spin to explore.

        Args:
            navigator: BasicNavigator instance
            next_landmark: Landmark dictionary with 'name' key
            frontier_dict: Dictionary of frontier positions

        Returns:
            bool: True if navigation succeeded, False otherwise
        """
        approach_pose = Pose()
        approach_pose.position.x = frontier_dict[next_landmark['name']]['position_xy'][0]
        approach_pose.position.y = frontier_dict[next_landmark['name']]['position_xy'][1]
        approach_pose.position.z = 0.0

        robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(self.node.robot_pose)
        approach_x, approach_y, _ = pose_msg_to_xyyaw(approach_pose)
        # Face the unexplored side. The frontier already knows which way that
        # is -- it is the outward normal worked out from the unknown cells
        # around the boundary -- so use it rather than the bearing we happened
        # to approach from, which points straight at whatever is behind.
        approach_yaw = frontier_dict[next_landmark['name']].get('yaw')
        if approach_yaw is None:
            approach_yaw = np.arctan2(approach_y - robot_y, approach_x - robot_x)
        quat = yaw_to_quaternion(approach_yaw)
        approach_pose.orientation.x = quat[0]
        approach_pose.orientation.y = quat[1]
        approach_pose.orientation.z = quat[2]
        approach_pose.orientation.w = quat[3]

        approach_marker = xyyaw_to_marker(rclpy.time.Time(), "Approach", approach_x, approach_y, approach_yaw,
                                          rgb=(0.0, 1.0, 0.0), scale=(1.2, 0.25, 0.25))
        self.node.goal_marker_pub.publish(approach_marker)
        self.node.get_logger().info(f"Approaching {next_landmark['name']}")

        nav_result = goToPose(navigator, approach_pose)

        if getattr(self.node, 'goal_reached', False):

            return True   # read in passing while walking; nothing left to inspect
        if nav_result == False:
            return False

        self.node.get_logger().info(f"Spin to look around")
        spin_wait(navigator, 6.28)
        time.sleep(1.0)
        # Done with this one. The boundary is recomputed every pass and a
        # six-second sweep rarely pushes it out of existence, so without this
        # the chooser names the same spot again and the goal never moves.
        note_visited(approach_x, approach_y)
        return True

    def handle_sign_landmark(self, navigator, next_landmark, landmark_pose, costmap_image, vlm_sign_dir):
        """Handle sign landmark: approach, read sign, and extract directions.

        Args:
            navigator: BasicNavigator instance
            next_landmark: Landmark dictionary with 'name' key
            landmark_pose: Landmark pose
            costmap_image: Costmap image for VLM processing
            vlm_sign_dir: Use VLM for sign direction conversion
        """
        approach_dist = -1.5
        landmark_pose, approach_pose = self.get_landmark_approach_pose(next_landmark['name'], approach_dist)
        approach_x, approach_y, approach_yaw = pose_msg_to_xyyaw(approach_pose)
        approach_marker = xyyaw_to_marker(rclpy.time.Time(), "Approach", approach_x, approach_y, approach_yaw,
                                          rgb=(0.0, 1.0, 0.0), scale=(1.2, 0.25, 0.25))
        self.node.goal_marker_pub.publish(approach_marker)

        self.node.get_logger().info(f"Approaching {next_landmark['name']}")
        nav_result = goToPose(navigator, approach_pose)
        if getattr(self.node, 'goal_reached', False):
            return True   # read in passing while walking; nothing left to inspect

        _, sign_class, sign_idx = next_landmark['name'].split('_')
        sign_idx = int(sign_idx)

        approached = getattr(self.node, '_sign_approached', set())
        approached.add(sign_idx)
        self.node._sign_approached = approached
        if nav_result != False:
            pan_to_target(self.node, landmark_pose)
            # Standing in front of it, the passive reader now has a big crop:
            # give it a few seconds before deciding the sign is done. The
            # photograph itself still goes to the chooser with the map.
            t_end = time.monotonic() + 8.0
            while time.monotonic() < t_end:
                view = self.node.sign_views.get(sign_idx)
                if view and view.get('entries'):
                    break
                time.sleep(0.5)
            view = self.node.sign_views.get(sign_idx)
            self.node.get_logger().info(
                f"Inspected {next_landmark['name']}: "
                + ("reads " + ", ".join(e['label'] + ' ' + e['arrow'] for e in view['entries'])
                   if view and view.get('entries') else "still unread; its photo goes to the chooser with the map"))

        relative_pan(self.node, 'center')
        # Visited, but a sign has no "number" to record -- what it says now
        # reaches the VLM as a photograph instead.
        self.node.landmark_db.mark_visited("a directional sign", sign_idx)

    def handle_person_landmark(self, navigator, next_landmark, landmark_pose, costmap_image):
        """Handle person landmark: approach and conduct HRI dialogue.

        Args:
            navigator: BasicNavigator instance
            next_landmark: Landmark dictionary with 'name' key
            landmark_pose: Landmark pose
            costmap_image: Costmap image for HRI context
        """
        approach_dist = -2.5
        landmark_pose, approach_pose = self.get_landmark_approach_pose(next_landmark['name'], approach_dist)
        approach_x, approach_y, approach_yaw = pose_msg_to_xyyaw(approach_pose)
        approach_marker = xyyaw_to_marker(rclpy.time.Time(), "Approach", approach_x, approach_y, approach_yaw,
                                          rgb=(0.0, 1.0, 0.0), scale=(1.2, 0.25, 0.25))
        self.node.goal_marker_pub.publish(approach_marker)

        self.node.get_logger().info(f"Approaching {next_landmark['name']}")
        nav_result = goToPose(navigator, approach_pose)
        if getattr(self.node, 'goal_reached', False):
            return True   # read in passing while walking; nothing left to inspect

        person_idx = int(next_landmark['name'].split('_')[-1])
        if nav_result == False:
            self.node.landmark_db.mark_visited("a person", person_idx)
            return

        self.node.get_logger().info("Pan Camera")
        pan_to_target(self.node, landmark_pose)
        time.sleep(1.0)

        robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(self.node.robot_pose)
        robot_facing = get_cardinal_direction(robot_yaw)
        self.node.hri_agent.initiate(costmap_image, robot_facing)
        new_info = self.node.hri_agent.get_new_info()

        obj_idx = person_idx
        self.node.landmark_db.landmark_db['a person']['info'][obj_idx] = new_info
        self.node.get_logger().info(f"Spoke with human, got new info: {self.node.landmark_db.landmark_db['a person']['info'][obj_idx]}")
        relative_pan(self.node, 'center')
        self.node.landmark_db.mark_visited("a person", person_idx)

    def _reachable_mask(self, g, info, rp):
        """Cells connected to the rig through standable ground, or None."""
        if rp is None:
            return None
        try:
            from scipy import ndimage
            free = (g >= 0) & (g < APPROACH_MAX_COST)
            lab, _ = ndimage.label(free, structure=np.ones((3, 3)))
            ix = int((rp.position.x - info.origin.position.x) / info.resolution)
            iy = int((rp.position.y - info.origin.position.y) / info.resolution)
            if not (0 <= ix < info.width and 0 <= iy < info.height):
                return None
            r = int(1.0 / info.resolution)
            win = lab[max(0, iy - r):iy + r + 1, max(0, ix - r):ix + r + 1]
            vals = win[win > 0]
            if vals.size == 0:
                return None
            # The rig may stand on an inflated cell; take the component that
            # dominates its immediate surroundings.
            region = int(np.bincount(vals).argmax())
            return lab == region
        except Exception:
            return None

    def _pick_side(self, a: Pose, b: Pose, landmark_xy=None) -> Pose:
        """Choose between the two candidate approach poses either side of a landmark.

        If neither is somewhere a person can stand, fall back to the nearest
        free cell around the landmark. Doors behind glass or set into recesses
        come back from the depth camera a metre past the wall, so a point 2 m
        along either side of the normal can land outside the corridor entirely
        -- the goal arrow then sits in the unknown beyond the wall and nobody
        can walk to it.
        """
        grid = getattr(self.node, 'costmap', None)
        info = getattr(grid, 'info', None)
        rp = getattr(self.node, 'robot_pose', None)

        def cell(p):
            if info is None or not grid.data:
                return None
            ix = int((p.position.x - info.origin.position.x) / info.resolution)
            iy = int((p.position.y - info.origin.position.y) / info.resolution)
            if 0 <= ix < info.width and 0 <= iy < info.height:
                return grid.data[iy * info.width + ix]
            return None

        def score(p):
            v = cell(p)
            cost = 0.0
            if v is None:
                cost += 100.0
            elif v < 0:
                cost += 50.0          # unknown
            elif v >= 100:
                cost += 100.0         # inside the wall
            else:
                cost += v / 100.0
            if rp is not None:
                cost += 0.1 * np.hypot(p.position.x - rp.position.x, p.position.y - rp.position.y)
            return cost

        best = a if score(a) <= score(b) else b
        v = cell(best)
        standable = v is not None and 0 <= v < APPROACH_MAX_COST
        # Free is not enough: the cell must be free all the way from the rig.
        # A door seen through a glass partition put its stand point on free
        # floor on the far side of the glass (lidar and depth both pass
        # through it); the carrier stood 2.6 m away for 20 s and gave up.
        if standable and info is not None and grid.data and rp is not None:
            g0 = np.asarray(grid.data, dtype=np.int16).reshape(info.height, info.width)
            reach0 = self._reachable_mask(g0, info, rp)
            if reach0 is not None:
                ix = int((best.position.x - info.origin.position.x) / info.resolution)
                iy = int((best.position.y - info.origin.position.y) / info.resolution)
                if not (0 <= ix < info.width and 0 <= iy < info.height and reach0[iy, ix]):
                    self.node.get_logger().info(
                        f"approach: ({best.position.x:.2f}, {best.position.y:.2f}) is free but not connected to the rig -- refitting")
                    standable = False
        if standable or landmark_xy is None or info is None or not grid.data:
            return best

        # Fallback: stand square in front of the wall the door is in.
        # The detected normal is unreliable and the detected position often
        # sits a metre past the wall (depth through glass / a recess), so both
        # are recovered from the costmap: fit a line to the LETHAL cells around
        # the door (that is the wall), project the door onto it, and stand
        # APPROACH_STAND_M out along the wall normal, on the robot's side,
        # facing the wall. Looking along the wall -- what "face the landmark"
        # produced when the landmark was behind the wall -- shows no plate.
        res = info.resolution
        g = np.asarray(grid.data, dtype=np.int16).reshape(info.height, info.width)
        lx, ly = float(landmark_xy[0]), float(landmark_xy[1])
        r = int(APPROACH_SEARCH_M / res)
        cx = int((lx - info.origin.position.x) / res); cy = int((ly - info.origin.position.y) / res)
        x0, x1 = max(0, cx - r), min(info.width, cx + r + 1)
        y0, y1 = max(0, cy - r), min(info.height, cy + r + 1)
        win = g[y0:y1, x0:x1]
        wys, wxs = np.nonzero(win >= 100)
        out = Pose(); out.orientation.w = 1.0
        if wxs.size >= 8:
            wx = info.origin.position.x + (wxs + x0 + 0.5) * res
            wy = info.origin.position.y + (wys + y0 + 0.5) * res
            near = np.hypot(wx - lx, wy - ly) < 2.0
            if near.sum() >= 8:
                wx, wy = wx[near], wy[near]
            P = np.stack([wx - wx.mean(), wy - wy.mean()], 1)
            _, _, vt = np.linalg.svd(P, full_matrices=False)
            tang = vt[0]; nrm = np.array([-tang[1], tang[0]])
            # Door projected onto the wall line.
            cxw, cyw = wx.mean(), wy.mean()
            proj = np.array([cxw, cyw]) + tang * np.dot([lx - cxw, ly - cyw], tang)
            cands = [proj + nrm * APPROACH_STAND_M, proj - nrm * APPROACH_STAND_M]
            reach = self._reachable_mask(g, info, rp)
            def standable(pt):
                ix = int((pt[0] - info.origin.position.x) / res); iy = int((pt[1] - info.origin.position.y) / res)
                if not (0 <= ix < info.width and 0 <= iy < info.height):
                    return False
                if reach is not None and not reach[iy, ix]:
                    return False          # free, but not free all the way from the rig
                return 0 <= g[iy, ix] < APPROACH_MAX_COST
            ok = [c for c in cands if standable(c)]
            if ok:
                if rp is not None:
                    ok.sort(key=lambda c: np.hypot(c[0] - rp.position.x, c[1] - rp.position.y))
                st = ok[0]
                out.position.x, out.position.y = float(st[0]), float(st[1])
                yaw = math.atan2(proj[1] - st[1], proj[0] - st[0])     # square onto the wall
                q = yaw_to_quaternion(yaw)
                out.orientation.x, out.orientation.y, out.orientation.z, out.orientation.w = q
                self.node.get_logger().info(
                    f"approach: wall-fitted stand point ({st[0]:.2f}, {st[1]:.2f}) facing the door "
                    f"projected to ({proj[0]:.2f}, {proj[1]:.2f}); detected door was {np.hypot(lx-proj[0], ly-proj[1]):.1f} m off the wall")
                return out
        # No wall to fit: nearest standable cell, facing the detected position.
        reach = self._reachable_mask(g, info, rp)
        ok_win = (win >= 0) & (win < APPROACH_MAX_COST)
        if reach is not None:
            ok_win &= reach[y0:y1, x0:x1]
        ys, xs = np.nonzero(ok_win)
        if xs.size == 0:
            return best
        fx = info.origin.position.x + (xs + x0 + 0.5) * res
        fy = info.origin.position.y + (ys + y0 + 0.5) * res
        d_land = np.hypot(fx - lx, fy - ly)
        d_robot = (np.hypot(fx - rp.position.x, fy - rp.position.y) if rp is not None else np.zeros_like(d_land))
        k = int(np.argmin(np.abs(d_land - APPROACH_STAND_M) + 0.3 * d_robot + win[ys, xs] / 100.0))
        out.position.x, out.position.y = float(fx[k]), float(fy[k])
        yaw = math.atan2(ly - out.position.y, lx - out.position.x)
        q = yaw_to_quaternion(yaw)
        out.orientation.x, out.orientation.y, out.orientation.z, out.orientation.w = q
        return out

    def get_landmark_approach_pose(self, landmark_name, x=-2):
        """Get the approach pose for a landmark.

        Computes a pose at distance x in the landmark's local frame,
        then transforms to map frame.

        Args:
            landmark_name: Name of landmark (e.g., "Unvisited_door_0")
            x: Distance from landmark (negative means behind)

        Returns:
            tuple: (landmark_pose, approach_pose_map)
        """
        visited_status = landmark_name.split('_')[0]
        landmark_class, landmark_index = landmark_name.split('_')[1:]
        landmark_class = "a " + landmark_class

        # The trailing number is the array index for Visited and Unvisited
        # alike (labels now hold the room number, not an id). The old branch
        # searched labels for the whole name, never matched, and silently fell
        # back to index 0 -- so a Visited door sent the rig to door 0 instead.
        landmark_index = int(landmark_index)

        landmark_position = self.node.landmark_db.landmark_db[landmark_class]['positions'][landmark_index]
        landmark_orientation = self.node.landmark_db.landmark_db[landmark_class]['orientations'][landmark_index]

        landmark_tf = TransformStamped()
        landmark_tf.header.frame_id = 'map'
        landmark_tf.child_frame_id = landmark_name
        landmark_tf.transform.translation.x = landmark_position[0]
        landmark_tf.transform.translation.y = landmark_position[1]
        landmark_tf.transform.translation.z = landmark_position[2]
        landmark_tf.transform.rotation.x = landmark_orientation[0]
        landmark_tf.transform.rotation.y = landmark_orientation[1]
        landmark_tf.transform.rotation.z = landmark_orientation[2]
        landmark_tf.transform.rotation.w = landmark_orientation[3]

        # get landmark pose
        landmark_pose = Pose()
        landmark_pose.position.x = landmark_position[0]
        landmark_pose.position.y = landmark_position[1]
        landmark_pose.position.z = landmark_position[2]
        landmark_pose.orientation.w = 1.0

        # get the approach pose in the landmark frame
        approach_pose = Pose()
        approach_pose.position.x = x
        approach_pose.position.y = 0.0
        approach_pose.position.z = 0.0
        approach_pose.orientation.w = 1.0
        approach_pose_map = do_transform_pose(approach_pose, landmark_tf)

        # The landmark's x-axis is the surface normal from detection.py, whose
        # sign is undefined -- the cross product of two bbox-corner vectors
        # flips with corner order, and the code that oriented it toward the
        # camera is commented out there. Half the time "2 m in front of the
        # door" therefore lands 2 m BEHIND it, inside the wall or out in the
        # unknown, which is where the green goal arrow kept appearing. Try both
        # sides and keep the one that is standable and nearer the rig.
        mirrored = Pose()
        mirrored.position.x = -x
        mirrored.orientation.w = 1.0
        alt_map = do_transform_pose(mirrored, landmark_tf)
        approach_pose_map = self._pick_side(approach_pose_map, alt_map,
                                            (landmark_position[0], landmark_position[1]))

        # Face the landmark from the stand point -- NOT the direction of travel.
        # The old arctan2(approach - robot) pointed the arrow along the corridor
        # the rig walked in on, i.e. parallel to the wall; a plate is read
        # square-on, and that heading is what _pick_side computed.
        approach_x, approach_y, _ = pose_msg_to_xyyaw(approach_pose_map)
        approach_yaw = np.arctan2(landmark_position[1] - approach_y,
                                  landmark_position[0] - approach_x)
        quat = yaw_to_quaternion(approach_yaw)
        approach_pose_map.orientation.x = quat[0]
        approach_pose_map.orientation.y = quat[1]
        approach_pose_map.orientation.z = quat[2]
        approach_pose_map.orientation.w = quat[3]

        self.node.publish_tf(approach_pose_map, "goal")
        return landmark_pose, approach_pose_map