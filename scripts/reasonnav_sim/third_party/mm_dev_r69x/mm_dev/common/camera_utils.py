#!/usr/bin/env python3
"""Camera control utilities for pan-tilt operations."""

import time
import numpy as np
from geometry_msgs.msg import Pose
from sensor_msgs.msg import JointState
from mm_dev.common.tf_utils import pose_msg_to_xyyaw
from mm_dev.common.config_loader import VLMNavConfig


def pan_to_target(node, target_pose: Pose):
    """Pan camera to look at a target pose.

    Args:
        node: VLMNav node instance with publishers and robot state
        target_pose: Target pose to look at
    """
    target_x = target_pose.position.x
    target_y = target_pose.position.y
    robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(node.robot_pose)
    yaw = -1 * np.arctan2(target_y - robot_y, target_x - robot_x) + robot_yaw
    yaw = (yaw + np.pi) % (2 * np.pi) - np.pi

    pan_tilt_msg = JointState()
    pan_tilt_msg.name = ['pan_joint', 'tilt_joint']
    pan_tilt_msg.position = [yaw, 0.0]

    start_time = time.time()
    node.pan_tilt_pub.publish(pan_tilt_msg)

    while node.pan_joint_state is None or abs(node.pan_joint_state - yaw) > 0.1:
        time.sleep(0.1)

        config = VLMNavConfig()
        pan_timeout = config.get('timeouts.pan_timeout', 5.0)
        if abs(time.time() - start_time) > pan_timeout:
            print("took too long")
            break


def relative_pan(node, direction: str):
    """Pan camera relative to current position.

    Args:
        node: VLMNav node instance with publishers and pan joint state
        direction: Direction to pan ('left', 'right', 'center', 'diag_left', 'diag_right')
    """
    # No pan-tilt on the handheld rig, so /joint_states never arrives and
    # pan_joint_state stays None -- the relative branches below would raise on
    # None + angle. Treat "no servo" as sitting at zero; the command is still
    # published, it just has no subscriber.
    cur_pan_position = node.pan_joint_state
    if cur_pan_position is None:
        cur_pan_position = 0.0
    pan_tilt_msg = JointState()
    pan_tilt_msg.name = ['pan_joint', 'tilt_joint']

    if direction == 'left':  # 90 deg to the left of cur pose
        pan_tilt_msg.position = [cur_pan_position + 1.57, 0.0]
    elif direction == 'diag_left':
        pan_tilt_msg.position = [cur_pan_position + 0.523599, 0.0]
    elif direction == 'right':
        pan_tilt_msg.position = [cur_pan_position - 1.57, 0.0]
    elif direction == 'diag_right':
        pan_tilt_msg.position = [cur_pan_position - 0.523599, 0.0]
    elif direction == 'center':
        pan_tilt_msg.position = [0.0, 0.0]

    node.pan_tilt_pub.publish(pan_tilt_msg)