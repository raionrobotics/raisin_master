#!/usr/bin/env python3
"""Landmark database management for VLM navigation system."""

import os

import numpy as np
from geometry_msgs.msg import Pose
from tf2_msgs.msg import TFMessage
from geometry_msgs.msg import TransformStamped


# How many observations a landmark's position averages over before the mean
# stops growing and becomes a decaying one. Keeping it finite matters: a purely
# cumulative mean would freeze the estimate after a few hundred frames, so a
# landmark first seen badly from across the corridor could never be corrected by
# a close-up view.
POSITION_AVG_MAX_N = int(os.environ.get('REASONNAV_LANDMARK_AVG_N', '20'))
# Sightings a landmark needs before the VLM is shown it. At ~9 detections/s a
# real door in view for half a second clears this; a one-frame false positive
# does not.
MIN_OBS_TO_SHOW = int(os.environ.get('REASONNAV_MIN_OBS', '4'))


class LandmarkDatabase:
    """Manage landmark detections and database operations."""

    def __init__(self, node):
        """Initialize landmark database.

        Args:
            node: ROS2 node instance for logging and publishing
        """
        self.node = node
        self.landmark_db = {}
        self.update_threshold = 1.5  # Default, can be overridden

    def add_det(self, obj_class: str, obj_pose: Pose, det_score: float, obj_label=None):
        """Add new detection to landmark database.

        Args:
            obj_class: Object class (e.g., "a door", "a person")
            obj_pose: Object pose in map frame
            det_score: Detection confidence score
            obj_label: Optional label for the landmark
        """
        if obj_class not in self.landmark_db:
            self.landmark_db[obj_class] = {
                # 'labels' holds what was actually READ off the landmark -- a
                # room number for a door -- and stays None when nothing was
                # read. Whether the robot has already been here is tracked
                # separately in 'visited'; overloading a filled-in label to
                # mean "visited" is what let landmark indices masquerade as
                # room numbers in the map handed to the VLM.
                'labels': [],
                'visited': [],
                # Inspected and found to carry nothing readable (a door with no
                # number plate, a "sign" that was a poster). Kept in the DB so it
                # keeps merging with itself, but never offered as a goal.
                'useless': [],
                'positions': [],
                'orientations': [],
                'detection_scores': [],
                # Observations averaged into each position so far.
                'obs_count': []
            }
            # Add directions field for directional signs
            if obj_class == "a directional sign":
                self.landmark_db[obj_class]['directions'] = []
            if obj_class == "a person":
                self.landmark_db[obj_class]['info'] = []

        self.landmark_db[obj_class]['labels'].append(obj_label)
        self.landmark_db[obj_class]['visited'].append(False)
        self.landmark_db[obj_class]['useless'].append(False)
        self.landmark_db[obj_class]['positions'].append([obj_pose.position.x, obj_pose.position.y, obj_pose.position.z])
        self.landmark_db[obj_class]['orientations'].append([obj_pose.orientation.x, obj_pose.orientation.y, obj_pose.orientation.z, obj_pose.orientation.w])
        self.landmark_db[obj_class]['detection_scores'].append(det_score)
        self.landmark_db[obj_class]['obs_count'].append(1)

        # Initialize directions as empty for directional signs
        if obj_class == "a directional sign" and 'directions' in self.landmark_db[obj_class]:
            self.landmark_db[obj_class]['directions'].append({})
        if obj_class == "a person" and 'info' in self.landmark_db[obj_class]:
            self.landmark_db[obj_class]['info'].append("")

    def update_det(self, obj_class: str, obj_pose: Pose, det_score: float, update_label=False, obj_label=None, person_update_distance=4.0):
        """Update existing detection or add new one.

        Args:
            obj_class: Object class
            obj_pose: Object pose in map frame
            det_score: Detection confidence score
            update_label: Whether to update the label
            obj_label: Optional new label
            person_update_distance: Special update distance for people

        Returns:
            int: Index of the updated/added landmark
        """
        update_dist = self.update_threshold
        if 'person' in obj_class:
            update_dist = max(person_update_distance, self.update_threshold)

        existing_pos = np.array(self.landmark_db[obj_class]['positions'])
        landmark_index = len(existing_pos)
        obj_position = np.array([obj_pose.position.x, obj_pose.position.y, obj_pose.position.z])

        if len(existing_pos) > 0:
            dist = np.linalg.norm(existing_pos[:, :2] - obj_position[:2], axis=1)
            min_idx = np.argmin(dist)
            min_dist = dist[min_idx]

            if min_dist < update_dist:
                entry = self.landmark_db[obj_class]
                # Average the position over observations instead of letting the
                # newest high-scoring frame overwrite it outright. A door's
                # projected position wanders by up to a metre frame to frame --
                # bbox corners land on different surfaces, depth drops out and
                # comes back -- and taking whichever frame scored highest meant
                # the stored position was one sample of that wander, not the
                # middle of it. Detector scores saturate near 0.9, so the old
                # `>=` test fired almost every frame anyway: it was "latest
                # wins" wearing a confidence check.
                #
                # Anything reaching here is already within update_dist of the
                # landmark, so the merge test upstream has excluded gross
                # outliers and a plain mean needs no further guarding.
                counts = entry.setdefault('obs_count', [1] * len(entry['positions']))
                while len(counts) < len(entry['positions']):
                    counts.append(1)
                n = min(counts[min_idx] + 1, POSITION_AVG_MAX_N)
                counts[min_idx] = n
                prev = np.array(entry['positions'][min_idx], dtype=float)
                obs = np.array([obj_pose.position.x, obj_pose.position.y,
                                obj_pose.position.z], dtype=float)
                entry['positions'][min_idx] = list(prev + (obs - prev) / n)

                # Orientation stays best-score: averaging quaternions properly
                # is a different job, and the surface normal it carries is only
                # used to pick an approach pose.
                if det_score >= entry['detection_scores'][min_idx]:
                    entry['orientations'][min_idx] = [
                        obj_pose.orientation.x, obj_pose.orientation.y,
                        obj_pose.orientation.z, obj_pose.orientation.w]
                    entry['detection_scores'][min_idx] = det_score
                if update_label:
                    self.landmark_db[obj_class]['labels'][min_idx] = obj_label
                landmark_index = min_idx

        if landmark_index == len(existing_pos):
            self.add_det(obj_class, obj_pose, det_score, obj_label)

        return landmark_index

    def mark_useless(self, obj_class: str, landmark_index: int):
        entry = self.landmark_db.get(obj_class)
        if entry is None or not (0 <= landmark_index < len(entry['positions'])):
            return
        entry.setdefault('useless', [False] * len(entry['positions']))
        while len(entry['useless']) < len(entry['positions']):
            entry['useless'].append(False)
        entry['useless'][landmark_index] = True
        entry['visited'][landmark_index] = True

    def mark_visited(self, obj_class: str, landmark_index: int, label=None):
        """Record that the robot has inspected this landmark.

        `label` is whatever was read off it (a room number) or None when the
        inspection produced nothing legible. Either way the landmark stops
        being a candidate; only a real reading gets stored as the label.
        """
        entry = self.landmark_db.get(obj_class)
        if entry is None or not (0 <= landmark_index < len(entry['visited'])):
            return
        entry['visited'][landmark_index] = True
        if label is not None:
            entry['labels'][landmark_index] = label

    def get_landmark_pose(self, landmark_name: str) -> Pose:
        """Get pose of landmark from database.

        Args:
            landmark_name: Name of landmark (e.g., "Unvisited_door_0")

        Returns:
            Pose: Landmark pose in map frame
        """
        landmark_class, landmark_index = landmark_name.split('_')[1:]
        landmark_class = "a " + landmark_class
        landmark_index = int(landmark_index)
        landmark_position = self.landmark_db[landmark_class]['positions'][landmark_index]
        landmark_orientation = self.landmark_db[landmark_class]['orientations'][landmark_index]

        pose_msg = Pose()
        pose_msg.position.x = landmark_position[0]
        pose_msg.position.y = landmark_position[1]
        pose_msg.position.z = landmark_position[2]
        pose_msg.orientation.x = landmark_orientation[0]
        pose_msg.orientation.y = landmark_orientation[1]
        pose_msg.orientation.z = landmark_orientation[2]
        pose_msg.orientation.w = landmark_orientation[3]
        return pose_msg

    def get_landmarks_dict(self) -> dict:
        """Convert landmark database to dict format for visualization.

        Returns:
            dict: Landmark data with positions and metadata
        """
        output = {}
        for obj_class, obj_data in self.landmark_db.items():
            if obj_class.startswith("a "):
                obj_class_name = obj_class[2:]
            else:
                obj_class_name = obj_class

            visited_col = obj_data.get('visited', [])
            useless_col = obj_data.get('useless', [])
            counts = obj_data.get('obs_count', [])
            for landmark_index in range(len(obj_data['positions'])):
                # Not enough sightings to trust. A pillar edge or a reflection
                # in glass gets detected once or twice as the camera sweeps past
                # and never again; a real door keeps being seen. Hide these from
                # the VLM until they earn it (still tracked, still merging).
                n_obs = counts[landmark_index] if landmark_index < len(counts) else 1
                if n_obs < MIN_OBS_TO_SHOW and obj_class_name != 'person':
                    continue
                # Inspected and empty: not a goal, not a clue. Drop it entirely
                # from what the VLM sees rather than let a numberless door pose
                # as a visited-but-unread one.
                if landmark_index < len(useless_col) and useless_col[landmark_index]:
                    continue
                # The trailing number is ALWAYS the array index, never the room
                # number. get_landmark_pose parses it straight back into
                # positions[...], so a name like "Visited_door_1143" used to
                # index past the end of the list -- and, worse, told the VLM
                # there was a room 1143 here when the reading had failed.
                seen = (visited_col[landmark_index]
                        if landmark_index < len(visited_col) else False)
                prefix = 'Visited' if seen else 'Unvisited'
                name = f"{prefix}_{obj_class_name}_{landmark_index}"

                position = obj_data['positions'][landmark_index]

                output_entry = {
                    'position_xy': position[:2],
                }
                # What was read off it, if anything. Kept under its own key so
                # an unreadable landmark simply has no room number rather than
                # an invented one.
                reading = obj_data['labels'][landmark_index]
                if reading is not None:
                    output_entry['room'] = reading

                # Add directional information for signs
                if obj_class_name == "directional sign":
                    try:
                        directions = self.landmark_db[f"a {obj_class_name}"]["directions"][landmark_index]
                        if directions:
                            output_entry['directions'] = directions
                    except:
                        self.node.get_logger().info(f"no directions for sign {name}")

                if obj_class_name == "person":
                    try:
                        info = self.landmark_db[f"a {obj_class_name}"]["info"][landmark_index]
                        if info:
                            output_entry['info'] = info
                    except:
                        self.node.get_logger().info(f"no info for person {name}")

                output[name] = output_entry
        return output

    def pub_landmark(self, obj_class: str, landmark_index: int, landmark_vis_pub):
        """Publish landmark transform for RViz visualization.

        Args:
            obj_class: Object class
            landmark_index: Index of landmark in database
            landmark_vis_pub: ROS publisher for TF messages
        """
        position = self.landmark_db[obj_class]['positions'][landmark_index]
        orientation = self.landmark_db[obj_class]['orientations'][landmark_index]
        label = self.landmark_db[obj_class]['labels'][landmark_index]

        if label is None:
            name = f"Unvisited_{obj_class}_{landmark_index}"
        else:
            name = f"Visited_{obj_class}_{label}"

        transform = TransformStamped()
        transform.header.stamp = self.node.get_clock().now().to_msg()
        transform.header.frame_id = "map"
        transform.child_frame_id = name

        transform.transform.translation.x = position[0]
        transform.transform.translation.y = position[1]
        transform.transform.translation.z = position[2]
        transform.transform.rotation.x = orientation[0]
        transform.transform.rotation.y = orientation[1]
        transform.transform.rotation.z = orientation[2]
        transform.transform.rotation.w = orientation[3]

        tf_message = TFMessage(transforms=[transform])
        landmark_vis_pub.publish(tf_message)