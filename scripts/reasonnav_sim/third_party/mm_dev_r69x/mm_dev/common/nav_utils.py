#!/usr/bin/env python3
"""Navigation utility functions for VLM navigation system."""

import os
import time
import numpy as np
from geometry_msgs.msg import Pose, PoseStamped
from nav2_simple_commander.robot_navigator import BasicNavigator, TaskResult
from rclpy.duration import Duration
from action_msgs.msg import GoalStatus

# --- Handheld "walk there yourself" mode ------------------------------------
# How close the operator has to get before the rig counts as arrived, and how
# long to keep waiting before giving up on a goal they evidently are not
# walking to.
ARRIVE_RADIUS = float(os.environ.get('REASONNAV_ARRIVE_RADIUS', '1.5'))
ARRIVE_TIMEOUT = float(os.environ.get('REASONNAV_ARRIVE_TIMEOUT', '90'))
# Give up early when the gap stops closing. The VLM picks from a map that is
# still being built, so it will sometimes name a frontier that the next costmap
# update has already swallowed, or a spot behind a wall -- goals that are not
# merely far but unreachable. Waiting out the full timeout on those wastes a
# minute and a half of walking time each, and to the person carrying the rig it
# looks like the system has hung.
STALL_SECONDS = float(os.environ.get('REASONNAV_STALL_SECONDS', '20'))
STALL_PROGRESS_M = float(os.environ.get('REASONNAV_STALL_PROGRESS', '0.5'))
# Radius, in metres, that has to be clear of obstacles for a goal to be worth
# walking to at all. Roughly the footprint's half-width.
GOAL_CLEARANCE = float(os.environ.get('REASONNAV_GOAL_CLEARANCE', '0.4'))
LETHAL_COST = 100          # OccupancyGrid scale, as voxel_costmap publishes it
# Pause after arriving at a frontier so the carrier can sweep the rig around,
# standing in for the base spin the wheeled robot would do.
# Short: the VLM query that follows takes ~3 s anyway and frontiers refresh at
# 1 Hz in the background, so the carrier's turn overlaps the thinking.
SWEEP_SECONDS = float(os.environ.get('REASONNAV_SWEEP_SECONDS', '2'))

_POSE_SOURCE = None

# Goals we are done with for now -- either walked at and not reached, or
# reached and swept -- as (x, y, monotonic_time). Frontiers
# live only in the current costmap and never enter the landmark database, so
# there is nothing to mark visited on them -- without this the chooser is free
# to name the same unreachable spot on the very next pass, and the rig stands
# there being told to walk somewhere it cannot get to.
_ABANDONED = []
ABANDON_TTL = float(os.environ.get('REASONNAV_ABANDON_TTL', '120'))
ABANDON_RADIUS = float(os.environ.get('REASONNAV_ABANDON_RADIUS', '2.0'))


def note_abandoned(x, y):
    _ABANDONED.append((float(x), float(y), time.monotonic()))


def note_visited(x, y):
    """Record a frontier we actually reached and swept.

    Arriving at a frontier does not make it stop being one: the boundary is
    recomputed from the costmap every pass, and standing on it for six seconds
    rarely pushes it far enough to disappear. Without this the chooser keeps
    naming the spot the carrier is already standing on, and from the outside
    the goal simply never changes.
    """
    _ABANDONED.append((float(x), float(y), time.monotonic()))


def recently_abandoned(x, y):
    """True if this spot was given up on and has not been forgiven yet.

    The TTL matters: a goal can be unreachable now and fine later, once the
    costmap has filled in or the carrier has come at it from another corridor.
    """
    now = time.monotonic()
    _ABANDONED[:] = [a for a in _ABANDONED if now - a[2] < ABANDON_TTL]
    return any(np.hypot(x - ax, y - ay) < ABANDON_RADIUS
               for ax, ay, _ in _ABANDONED)


def attach_pose_source(node):
    """Give this module a live robot pose.

    goToPose only receives the navigator, which on a handheld rig knows nothing
    about where anyone is. vlm_nav already maintains `robot_pose` in the map
    frame from its own TF timer, and that timer runs on the executor thread
    while the main loop blocks in a handler -- so the pose keeps advancing while
    we wait here.
    """
    global _POSE_SOURCE
    _POSE_SOURCE = node


def _goal_blocked(gx, gy):
    """True if the costmap says nobody could stand at this goal.

    Checked before the wait rather than during it. The stall detector will
    eventually notice that a goal inside a wall is not getting closer, but only
    after twenty seconds of the carrier standing there wondering -- and the
    costmap already knows the answer the moment the goal is named.

    Unknown is not blocked: a goal on the edge of the map is exactly the kind
    worth walking to.
    """
    src = _POSE_SOURCE
    grid = getattr(src, 'costmap', None) if src is not None else None
    info = getattr(grid, 'info', None)
    if info is None or not grid.data:
        return False                      # nothing to judge with; let it try

    res = info.resolution
    ix = int((gx - info.origin.position.x) / res)
    iy = int((gy - info.origin.position.y) / res)
    r = max(1, int(round(GOAL_CLEARANCE / res)))
    data = np.asarray(grid.data, dtype=np.int16).reshape(info.height, info.width)
    y0, y1 = max(0, iy - r), min(info.height, iy + r + 1)
    x0, x1 = max(0, ix - r), min(info.width, ix + r + 1)
    if y1 <= y0 or x1 <= x0:
        return False
    return bool((data[y0:y1, x0:x1] >= LETHAL_COST).any())


def _walk_there(navigator, pose):
    """Hold the goal until the person carrying the rig reaches it.

    Reporting the move as instantly done (what this used to do) meant the goal
    changed every few seconds -- about 5 s for a frontier -- so a goal 40 m away
    was replaced long before anyone could walk to it, and the door handler ran
    its OCR from wherever the camera happened to be pointing rather than in
    front of the door. Waiting fixes both: the goal stays put, and inspection
    starts on arrival.
    """
    gx, gy = pose.position.x, pose.position.y
    log = navigator.get_logger()
    if _POSE_SOURCE is None:
        log.warn('REASONNAV_NO_NAV: no pose source attached; not waiting.')
        return True

    if _goal_blocked(gx, gy):
        log.info(f'BLOCKED ({gx:.2f}, {gy:.2f}): obstacle within '
                 f'{GOAL_CLEARANCE:.1f} m of the goal. Asking again now.')
        note_abandoned(gx, gy)
        return False

    log.info(f'WALK TO ({gx:.2f}, {gy:.2f}) -- waiting until within '
             f'{ARRIVE_RADIUS:.1f} m (giving up after {ARRIVE_TIMEOUT:.0f} s)')
    deadline = time.monotonic() + ARRIVE_TIMEOUT
    last_log = 0.0
    best = None            # closest we have been to this goal
    best_at = time.monotonic()
    while time.monotonic() < deadline:
        if getattr(_POSE_SOURCE, 'goal_reached', False):
            log.info('target read while walking -- no need to reach this goal')
            return True
        here = getattr(_POSE_SOURCE, 'robot_pose', None)
        if here is not None:
            dx = gx - here.position.x
            dy = gy - here.position.y
            dist = float(np.hypot(dx, dy))
            if dist <= ARRIVE_RADIUS:
                log.info(f'ARRIVED ({dist:.2f} m from goal)')
                return True
            now = time.monotonic()
            if best is None or dist < best - STALL_PROGRESS_M:
                best, best_at = dist, now
            elif now - best_at > STALL_SECONDS:
                log.info(f'UNREACHABLE ({gx:.2f}, {gy:.2f}): no progress for '
                         f'{STALL_SECONDS:.0f} s, still {dist:.1f} m away. '
                         'Picking something else.')
                note_abandoned(gx, gy)
                return False
            if now - last_log > 2.0:
                last_log = now
                log.info(f'  walk: {dist:5.1f} m to go')
        time.sleep(0.2)

    log.info(f'GAVE UP on ({gx:.2f}, {gy:.2f}) after {ARRIVE_TIMEOUT:.0f} s')
    note_abandoned(gx, gy)
    return False


def _no_nav():
    """True on a rig with no drivable base (handheld).

    Every landmark handler routes its motion through goToPose/spin_wait. With no
    bt_navigator (and no wheels) those block forever on 'NavigateToPose action
    server not available', which stalls the perceive -> visualise -> reason loop.
    Reporting the move as done lets that loop keep running while a human walks
    the rig around.
    """
    return bool(os.environ.get('REASONNAV_NO_NAV'))


def goToPose(navigator: BasicNavigator, pose: Pose, midpt_dist=None):
    """Navigate to a pose using Nav2.

    Args:
        navigator: BasicNavigator instance
        pose: Target pose in map frame
        midpt_dist: Optional distance threshold to stop early

    Returns:
        bool: True if navigation succeeded, False otherwise
    """
    if _no_nav():
        return _walk_there(navigator, pose)

    goal_pose = PoseStamped()
    goal_pose.header.frame_id = 'map'
    goal_pose.header.stamp = navigator.get_clock().now().to_msg()
    goal_pose.pose = pose
    navigator.goToPose(goal_pose)
    i = 0
    last_dist = -1

    while not navigator.isTaskComplete():
        i = i + 1
        feedback = navigator.getFeedback()

        if feedback and i % 10 == 0:
            curr_dist = feedback.distance_remaining
            navigator.get_logger().info(f"Distance remaining: {curr_dist:.2f}")

            # Check if we're close enough to goal (within robot length)
            robot_length = 0.8  # TODO: Get from config
            if np.abs(curr_dist - last_dist) < robot_length and feedback.distance_remaining <= robot_length:
                print('Close enough to goal, considering navigation successful')
                navigator.cancelTask()
                return True

            # Midpoint flag
            if midpt_dist and feedback.distance_remaining <= midpt_dist:
                print('Midpoint reached, stopping navigation')
                navigator.cancelTask()
                return True

            # Navigation timeout
            if Duration.from_msg(feedback.navigation_time) > Duration(seconds=240.0):
                print('Navigation timeout exceeded')
                navigator.cancelTask()
                return False

            last_dist = curr_dist

        # Check navigation status directly
        if GoalStatus and hasattr(navigator, 'getGoalStatus'):
            status = navigator.getGoalStatus()
            if status in [GoalStatus.ABORTED, GoalStatus.REJECTED]:
                print(f'Navigation goal failed with status: {status}')
                return False

        time.sleep(1.0)

    # Process final result
    result = navigator.getResult()
    if result == TaskResult.SUCCEEDED:
        print('Goal succeeded!')
        return True
    elif result == TaskResult.CANCELED:
        print('Goal was canceled!')
        return False
    elif result == TaskResult.FAILED:
        print('Goal failed!')
        return False
    else:
        print('Goal has an invalid return status!')
        return False


def spin_wait(navigator: BasicNavigator, radians: float):
    """Spin the robot by a given angle.

    Args:
        navigator: BasicNavigator instance
        radians: Angle to spin in radians
    """
    if _no_nav():
        # The wheeled robot spins here to sweep the area; a carrier has to be
        # given time to do the same by hand, or the loop races on before the
        # camera has seen anything new.
        navigator.get_logger().info(
            f'SWEEP: turn the rig about {np.degrees(radians):.0f} deg '
            f'({SWEEP_SECONDS:.0f} s)')
        time.sleep(SWEEP_SECONDS)
        return
    navigator.spin(radians, time_allowance=30)
    while not navigator.isTaskComplete():
        time.sleep(1.0)
    result = navigator.getResult()
    if result == TaskResult.SUCCEEDED:
        print('Goal succeeded!')
    elif result == TaskResult.CANCELED:
        print('Goal was canceled!')
    elif result == TaskResult.FAILED:
        print('Goal failed!')
    else:
        print('Goal has an invalid return status!')