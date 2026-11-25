#!/usr/bin/env python3

from geometry_msgs.msg import PoseStamped, Pose, Transform, Polygon, Point32
from nav_msgs.msg import Odometry
from nav2_simple_commander.robot_navigator import BasicNavigator, TaskResult
import rclpy
from rclpy.node import Node
from rclpy.duration import Duration
# from dotenv import load_dotenv
# from openai import OpenAI
# import requests
import os
from tf2_ros import TransformStamped
from tf2_ros import TransformListener, Buffer
import threading
import numpy as np
import time
from nav2_msgs.msg import Costmap
from mm_dev.common.tf_utils import get_tf, transform_msg_to_xyyaw, xyyaw_to_pose_msg, transform_msg_to_pose_msg
from mm_dev.common.costmap_2d import PyCostmap2D
from mm_dev.common.footprint_collision_checker import FootprintCollisionChecker
from mm_dev.frontier_detection.frontier_detector import get_frontiers, visualize_frontiers
from mm_dev.common.vis_utils import xyyaw_to_marker
from visualization_msgs.msg import Marker, MarkerArray
from rclpy.time import Time
from sensor_msgs.msg import Image
from sensor_msgs.msg import JointState
from cv_bridge import CvBridge
from rclpy.publisher import Publisher
import cv2

def goToPose(navigator, pose: Pose):
    goal_pose = PoseStamped()
    goal_pose.header.frame_id = 'map'
    goal_pose.header.stamp = navigator.get_clock().now().to_msg()
    goal_pose.pose = pose
    navigator.goToPose(goal_pose)
    i = 0
    while not navigator.isTaskComplete():
        # Do something with the feedback
        i = i + 1
        feedback = navigator.getFeedback()
        if feedback and i % 5 == 0:
            print(
                'Estimated time of arrival: '
                + '{0:.0f}'.format(
                    Duration.from_msg(feedback.estimated_time_remaining).nanoseconds
                    / 1e9
                )
                + ' seconds.'
            )

            # Some navigation timeout to demo cancellation
            if Duration.from_msg(feedback.navigation_time) > Duration(seconds=600.0):
                navigator.cancelTask()

            # # Some navigation request change to demo preemption
            # if Duration.from_msg(feedback.navigation_time) > Duration(seconds=18.0):
            #     self.navigator.goToPose(goal_pose)

    # Do something depending on the return code
    result = navigator.getResult()
    if result == TaskResult.SUCCEEDED:
        print('Goal succeeded!')
    elif result == TaskResult.CANCELED:
        print('Goal was canceled!')
    elif result == TaskResult.FAILED:
        print('Goal failed!')
    else:
        print('Goal has an invalid return status!')

# function that takes a target pose in map coordinates computes the pan angle, and publishes the pan angle to the pan_tilt controller
def look_at_target(target_pose:Pose, robot_xyyaw:Pose, pan_tilt_pub:Publisher):
    target_x = target_pose.position.x
    target_y = target_pose.position.y
    robot_x, robot_y, robot_yaw = robot_xyyaw
    yaw = -1*np.arctan2(target_y - robot_y, target_x - robot_x)+robot_yaw
    pan_tilt_msg = JointState()
    pan_tilt_msg.name = ['pan_joint', 'tilt_joint']
    pan_tilt_msg.position = [yaw, 0.0]
    pan_tilt_pub.publish(pan_tilt_msg)
    time.sleep(1)
TARGET = "Room 3018"

def main(args=None):
    rclpy.init(args=args)
    navigator = BasicNavigator()
    navigator.get_logger().info('Waiting for nav2 to be active...')
    # navigator.waitUntilNav2Active(localizer='waypoint_follower')
    navigator.get_logger().info('Nav2 is active!')

    tf_buffer = Buffer()
    tf_listener = TransformListener(tf_buffer, navigator)

    bridge = CvBridge()
    marker_pub = navigator.create_publisher(MarkerArray, 'frontiers', 10)
    frontier_image_pub = navigator.create_publisher(Image, 'frontier_image', 10)
    pan_tilt_pub = navigator.create_publisher(JointState, '/pan_tilt/joint_command', 10)

    pts = [ [0.369, 0.25], [0.369, -0.25], [-0.369, -0.25], [-0.369, 0.25] ]
    robot_footprint_m = Polygon()
    for pt in pts:
        p = Point32()
        p.x = pt[0]
        p.y = pt[1]
        robot_footprint_m.points.append(p)
    # navigator.spin(spin_dist=6.28)
    while not navigator.isTaskComplete():
        time.sleep(1)
    while rclpy.ok():
        # get global costmap
        costmap:Costmap = navigator.getGlobalCostmap()
        footprint_checker = FootprintCollisionChecker()
        py_costmap = PyCostmap2D(costmap)
        footprint_checker.setCostmap(py_costmap)
        navigator.get_logger().info('Received costmap message')
        to_frame_rel = 'map'
        from_frame_rel = 'base_link'
        robot_tf:Transform = get_tf(to_frame_rel, from_frame_rel, rclpy.time.Time(), tf_buffer)
        if robot_tf is None:
            navigator.get_logger().info(f'Could not get transform from {to_frame_rel} to {from_frame_rel}')
            continue
        
        frontiers_map, frontiers_world, _ = get_frontiers(costmap, robot_tf)
        if len(frontiers_world) == 0:
            navigator.get_logger().info('No frontiers this iteration; continuing (handheld viz)')
            time.sleep(1)
            continue
        robot_x, robot_y, robot_yaw = transform_msg_to_xyyaw(robot_tf)
        filtered_frontiers_map = []
        filtered_frontiers_world = []
        frontier_markers = []
        frontier_dists = []
        for i, (wx, wy) in enumerate(frontiers_world):
            yaw = np.arctan2(wy - robot_y, wx - robot_x)
            dist = np.sqrt((wx - robot_x)**2 + (wy - robot_y)**2)
            navigator.get_logger().info(f'Frontier {i}: {wx}, {wy}, {yaw}')
            navigator.get_logger().info(f'Frontier {i} dist: {dist}')
            mx, my = [int(j) for j in frontiers_map[i]]
            navigator.get_logger().info(f'Point cost: {py_costmap.getCostXY(mx, my)}')
            # get average cost of footprint by calling getCostXY for each point
            footprint_cost = 0
            for pt in robot_footprint_m.points:
                pt_mx = int(pt.x/costmap.metadata.resolution)
                pt_my = int(pt.y/costmap.metadata.resolution)
                try:
                    footprint_cost += py_costmap.getCostXY(mx+pt_mx, my+pt_my)
                except IndexError:
                    footprint_cost += 0
            footprint_cost /= len(robot_footprint_m.points)
            navigator.get_logger().info(f'Footprint cost: {footprint_cost}')
            if footprint_cost < 150:
                frontier_dists.append(dist)
                filtered_frontiers_map.append((mx, my))
                filtered_frontiers_world.append((wx, wy))
                marker = xyyaw_to_marker(rclpy.time.Time(),f"Frontier_{i}", wx, wy, yaw)
                frontier_markers.append(marker)
        markers = MarkerArray()
        # Clear last pass's arrows first, or the ones that no longer exist
        # stay drawn forever.
        wipe = Marker()
        wipe.header.frame_id = 'map'
        wipe.action = Marker.DELETEALL
        markers.markers = [wipe] + frontier_markers
        marker_pub.publish(markers)
                
        # publish costmap_image
        costmap_image = visualize_frontiers(filtered_frontiers_map, costmap, robot_tf)
        costmap_image_msg = bridge.cv2_to_imgmsg(costmap_image, encoding="bgra8")
        costmap_image_msg.header.frame_id = 'map'
        costmap_image_msg.header.stamp = navigator.get_clock().now().to_msg()
        frontier_image_pub.publish(costmap_image_msg)
        # look at frontier
        if len(filtered_frontiers_world) > 0:
            wx, wy = filtered_frontiers_world[0]
            yaw = np.arctan2(wy - robot_y, wx - robot_x)
            goal_pose = xyyaw_to_pose_msg(wx, wy, yaw)
            robot_pose = [robot_x, robot_y, robot_yaw]
            navigator.get_logger().info(f'Robot pose: {robot_pose}')
            navigator.get_logger().info(f'Going to goal: {goal_pose}')
            # goToPose(navigator, goal_pose)
            look_at_target(goal_pose, robot_pose, pan_tilt_pub)

        else:
            navigator.get_logger().info('No frontiers this iteration; continuing (handheld viz)')
            time.sleep(1)
            continue
        # choose closest dist frontier
        # min_index = np.argmin(frontier_dists)
        # wx, wy = filtered_frontiers_world[min_index]
        # yaw = np.arctan2(wy - robot_y, wx - robot_x)
        # goal_pose = xyyaw_to_pose_msg(wx, wy, yaw)
        # navigator.get_logger().info(f'Going to goal: {goal_pose}')
        # goToPose(navigator, goal_pose)
        time.sleep(1)

    rclpy.shutdown()

if __name__ == '__main__':
    main()