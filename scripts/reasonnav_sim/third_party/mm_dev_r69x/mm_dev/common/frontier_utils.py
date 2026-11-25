#!/usr/bin/env python3
"""Frontier detection and filtering utilities."""

import os
import time
import pickle
import numpy as np
from geometry_msgs.msg import Polygon, Transform
from mm_dev.common.tf_utils import get_tf, pose_msg_to_xyyaw, xyyaw_to_pose_msg
from mm_dev.common.vis_utils import xyyaw_to_marker
from mm_dev.common.costmap_2d import PyCostmap2D
from mm_dev.frontier_detection.frontier_detector import get_frontiers
from visualization_msgs.msg import MarkerArray
import rclpy


# nav2 cost value for unexplored ground.
NO_INFORMATION = 255
LETHAL_OBSTACLE = 254


def filter_frontiers_by_cost(frontiers_map, frontiers_world, py_costmap, robot_x, robot_y,
                              footprint_polygon: Polygon, max_cost: float, node,
                              frontier_yaws=None):
    """Filter frontiers based on footprint collision cost.

    Args:
        frontiers_map: List of frontier coordinates in map frame
        frontiers_world: List of frontier coordinates in world frame
        py_costmap: PyCostmap2D instance
        robot_x: Robot x position
        robot_y: Robot y position
        footprint_polygon: Robot footprint as Polygon
        max_cost: Maximum acceptable cost
        node: ROS2 node for logging

    Returns:
        tuple: (filtered_frontiers_map, filtered_frontiers_world, frontier_markers)
    """
    filtered_frontiers_map = []
    filtered_frontiers_world = []
    frontier_markers = []

    for i, (wx, wy) in enumerate(frontiers_world):
        # Face the unexplored side, not the way we walked up. arctan2 of
        # robot->frontier was the old choice and it points at whatever lies
        # beyond the boundary in the direction of travel -- usually the wall
        # the frontier is tucked against. Fall back to it only when the
        # outward normal could not be found.
        yaw = None
        if frontier_yaws is not None and i < len(frontier_yaws):
            yaw = frontier_yaws[i]
        if yaw is None:
            yaw = np.arctan2(wy - robot_y, wx - robot_x)
        mx, my = [int(j) for j in frontiers_map[i]]

        footprint_cost = compute_footprint_cost(py_costmap, mx, my, footprint_polygon)

        if footprint_cost < max_cost:
            filtered_frontiers_map.append((mx, my))
            filtered_frontiers_world.append(xyyaw_to_pose_msg(wx, wy, yaw))
            marker = xyyaw_to_marker(rclpy.time.Time(), f"Frontier_{i}", wx, wy, yaw)
            frontier_markers.append(marker)
        else:
            node.get_logger().warn(f'Frontier {i} at ({wx:.1f}, {wy:.1f}) filtered out: footprint cost {footprint_cost:.0f} >= {max_cost}')

    return filtered_frontiers_map, filtered_frontiers_world, frontier_markers


def compute_footprint_cost(py_costmap: PyCostmap2D, mx: int, my: int, footprint_polygon: Polygon) -> float:
    """Inflated cost at the frontier's centre cell, for the caller's `< max_cost` test.

    Centre only. The footprint polygon is axis-aligned in the MAP frame, so in
    a corridor running along x its +-0.4 m sides brushed the wall whenever the
    frontier sat a little off the corridor's centreline, and the corridor
    frontier right in front of the rig was thrown away (cost 254) -- leaving
    only frontiers behind it to choose from. Inflation already encodes the
    robot radius; whether the gap is wide enough is decided separately by the
    frontier detector's wall-to-wall test, and whether the goal cell itself is
    standable by nav_utils._goal_blocked.
    """
    try:
        centre = float(py_costmap.getCostXY(mx, my))
    except IndexError:
        return 0.0
    return 0.0 if centre == NO_INFORMATION else centre

def save_costmap_data(py_costmap: PyCostmap2D, robot_x: float, robot_y: float,
                      robot_yaw: float, save_dir: str):
    """Save costmap data to pickle file for debugging.

    Args:
        py_costmap: PyCostmap2D instance
        robot_x: Robot x position
        robot_y: Robot y position
        robot_yaw: Robot yaw orientation
        save_dir: Directory to save pickle file
    """
    filename = os.path.join(save_dir, f'costmap_{int(time.time())}.pkl')
    with open(filename, 'wb') as f:
        output_dict = {
            'costmap': py_costmap.get_costmap_as_image(),
            'robot_x': robot_x,
            'robot_y': robot_y,
            'robot_yaw': robot_yaw,
        }
        pickle.dump(output_dict, f)


def get_frontiers_with_filtering(costmap, robot_pose, tf_buffer, footprint_polygon,
                                 config, node, marker_pub):
    """Detect and filter frontiers from global costmap.

    Args:
        costmap: Global costmap
        robot_pose: Current robot pose
        tf_buffer: TF buffer for transforms
        footprint_polygon: Robot footprint polygon
        config: Configuration object
        node: ROS2 node for logging
        marker_pub: Publisher for frontier markers

    Returns:
        tuple: (filtered_frontiers_map, filtered_frontiers_world)
    """
    to_frame_rel = 'map'
    from_frame_rel = 'base_link'
    robot_tf: Transform = get_tf(to_frame_rel, from_frame_rel, rclpy.time.Time(), tf_buffer)
    py_costmap = PyCostmap2D(costmap)

    frontiers_map, frontiers_world, frontier_yaws = get_frontiers(costmap, robot_tf)

    if len(frontiers_world) == 0:
        node.get_logger().warn('No frontiers found, ending exploration')
        return None, None

    robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(robot_pose)
    # Debug dump only, and an expensive one: it pickles the whole costmap
    # (~640 KB) to disk on every pass of the navigation loop. With a VLM in the
    # loop the API latency hid the cost; ablation modes 3/4 have no such wait,
    # so this ran continuously and grew to 14 GB / 22k files while competing
    # with the detector for I/O. Opt in with REASONNAV_SAVE_COSTMAP=1.
    if os.environ.get('REASONNAV_SAVE_COSTMAP'):
        save_costmap_data(py_costmap, robot_x, robot_y, robot_yaw,
                          config.get('paths.costmap_save_dir'))

    max_cost = config.get('frontier.max_footprint_cost', 150)
    filtered_frontiers_map, filtered_frontiers_world, frontier_markers = filter_frontiers_by_cost(
        frontiers_map, frontiers_world, py_costmap, robot_x, robot_y,
        footprint_polygon, max_cost, node, frontier_yaws
    )

    # No marker publish here. This list still contains frontiers the caller is
    # about to drop (recently abandoned, already visited), and publishing it
    # painted stars in RViz that never appeared on the landmark map and led
    # nowhere. vlm_nav publishes from the list it actually hands to the VLM.
    return filtered_frontiers_map, filtered_frontiers_world