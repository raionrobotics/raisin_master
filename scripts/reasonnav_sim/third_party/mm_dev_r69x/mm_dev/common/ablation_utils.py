#!/usr/bin/env python3
"""Ablation study utilities for VLM navigation system."""

import numpy as np
from mm_dev.common.tf_utils import pose_msg_to_xyyaw


def choose_landmark_with_ablation(node, ablation_mode, keypoints_dict, nav_goal, costmap_image):
    """Choose next landmark based on ablation mode.

    Args:
        node: VLMNav node instance
        ablation_mode: Ablation mode (1-5)
        keypoints_dict: Dictionary of available landmarks and frontiers
        nav_goal: Navigation goal string
        costmap_image: Costmap image for VLM processing

    Returns:
        tuple: (vlm_result, next_landmark) or (None, next_landmark) for ablations
    """
    # Filter out visited landmarks for some ablations
    if ablation_mode == 3 or ablation_mode == 4:
        keypoints_dict = {k: v for k, v in keypoints_dict.items()
                         if not v['name'].startswith("Visited_")}

    if ablation_mode == 3:  # baseline for no vlm (random)
        rand_idx = np.random.choice(list(keypoints_dict.keys()))
        next_landmark = keypoints_dict[rand_idx]
        return None, next_landmark

    elif ablation_mode == 4:  # baseline for no vlm (closest)
        indices = list(keypoints_dict.keys())
        valid_indices = [i for i in indices if 'position' in keypoints_dict[i]]

        if valid_indices:
            positions = np.array([keypoints_dict[i]['position'] for i in valid_indices])
            robot_x, robot_y, robot_yaw = pose_msg_to_xyyaw(node.robot_pose)
            target = np.array([robot_x, robot_y])

            distances = np.sum((positions - target)**2, axis=1)

            closest_idx = valid_indices[np.argmin(distances)]
            next_landmark = keypoints_dict[closest_idx]
        else:
            rand_idx = np.random.randint(0, len(keypoints_dict))
            next_landmark = keypoints_dict[rand_idx]

        return None, next_landmark

    else:  # Use VLM for decision making
        vlm_result, next_landmark = node.vlm_choose_next_pose(nav_goal, costmap_image, keypoints_dict)
        return vlm_result, next_landmark


def prepare_landmarks_dict_for_vlm(keypoints_dict, ablation_mode):
    """Prepare landmarks dictionary based on ablation mode.

    Args:
        keypoints_dict: Original keypoints dictionary
        ablation_mode: Ablation mode

    Returns:
        dict: Modified keypoints dictionary for VLM processing
    """
    if ablation_mode == 5:
        # Remove position information for ablation 5
        vlm_keypt_dict = {}
    else:
        import copy
        vlm_keypt_dict = copy.deepcopy(keypoints_dict)
        for key, _ in vlm_keypt_dict.items():
            if 'Unvisited' in vlm_keypt_dict[key]['name']:
                name = "_".join(vlm_keypt_dict[key]['name'].split('_')[:-1])
                vlm_keypt_dict[key]['name'] = name

    return vlm_keypt_dict