#!/usr/bin/env python3
"""Geometric and mathematical utility functions for VLM navigation."""

import cv2
import numpy as np
import rclpy
from tf2_ros import Buffer, LookupException, ConnectivityException, ExtrapolationException
from rclpy.duration import Duration


def quaternion_to_yaw(quaternion):
    """Convert quaternion to yaw angle.

    Args:
        quaternion: List or tuple of [x, y, z, w]

    Returns:
        float: Yaw angle in radians
    """
    x, y, z, w = quaternion
    return np.arctan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def get_cardinal_direction(angle):
    """Convert angle in radians to closest cardinal direction.

    Args:
        angle: Angle in radians

    Returns:
        str: String representing cardinal direction (North, East, South, West)
    """
    # Normalize angle to [0, 2π)
    angle = angle % (2 * np.pi)

    # Map angle to cardinal direction
    if angle <= np.pi/8 or angle >= 15*np.pi/8:
        return "North"
    elif angle <= 3*np.pi/8:
        return "North-West"
    elif angle <= 5*np.pi/8:
        return "West"
    elif angle <= 7*np.pi/8:
        return "South-West"
    elif angle <= 9*np.pi/8:
        return "South"
    elif angle <= 11*np.pi/8:
        return "South-East"
    elif angle <= 13*np.pi/8:
        return "East"
    else:
        return "North-East"


def rotate_image_robot_up(image, tf_buffer: Buffer):
    """Rotate costmap so robot forward is up.

    Args:
        image: Input image to rotate
        tf_buffer: TF buffer for transform lookup

    Returns:
        Rotated image
    """
    try:
        map2robot = tf_buffer.lookup_transform(
            "base_link",
            "map",
            rclpy.time.Time(),
            Duration(seconds=1.0)
        )

        map_quat = [
            map2robot.transform.rotation.x,
            map2robot.transform.rotation.y,
            map2robot.transform.rotation.z,
            map2robot.transform.rotation.w
        ]
        map_yaw = quaternion_to_yaw(map_quat)

        opencv_angle = -(map_yaw * 180.0 / np.pi - 90.0)
        height, width = image.shape[:2]
        size = max(width, height)
        center = (size/2, size/2)
        rot_mat = cv2.getRotationMatrix2D(center, opencv_angle, 1.0)
        rotated_image = cv2.warpAffine(image, rot_mat, (size, size))
        return rotated_image
    except:
        return image


def update_sign_directions(sign_dict, tf_buffer: Buffer, node):
    """Transform sign directions from camera frame to global cardinal directions.

    Args:
        sign_dict: Dictionary of sign directions relative to camera
        tf_buffer: TF buffer for transform lookup
        node: ROS2 node for logging

    Returns:
        dict: Dictionary with global cardinal directions
    """
    if not sign_dict:
        return {}

    try:
        # Get camera orientation in the map frame
        camera_to_map = tf_buffer.lookup_transform(
            "map",
            "realsense_link",
            rclpy.time.Time(),
            Duration(seconds=1.0)
        )

        # Extract camera rotation in map frame
        camera_quat = [
            camera_to_map.transform.rotation.x,
            camera_to_map.transform.rotation.y,
            camera_to_map.transform.rotation.z,
            camera_to_map.transform.rotation.w
        ]
        camera_yaw = quaternion_to_yaw(camera_quat)

        # Define approximate mapping from camera-relative to global directions
        global_directions = {}

        # Map camera directions to global cardinal directions based on camera's yaw
        if 'left' in sign_dict:
            # Left is -90 degrees from camera forward
            left_angle = (camera_yaw + np.pi/2) % (2 * np.pi)
            global_directions[get_cardinal_direction(left_angle)] = sign_dict['left']

        if 'right' in sign_dict:
            # Right is +90 degrees from camera forward
            right_angle = (camera_yaw - np.pi/2) % (2 * np.pi)
            global_directions[get_cardinal_direction(right_angle)] = sign_dict['right']

        if 'forward' in sign_dict:
            # Forward is same as camera forward
            forward_angle = camera_yaw
            global_directions[get_cardinal_direction(forward_angle)] = sign_dict['forward']

        if 'backwards' in sign_dict:
            # Backwards is opposite of camera forward
            backwards_angle = (camera_yaw + np.pi) % (2 * np.pi)
            global_directions[get_cardinal_direction(backwards_angle)] = sign_dict['backwards']

        return global_directions

    except Exception as e:
        node.get_logger().error(f"TF Error: {e}")
        return {}