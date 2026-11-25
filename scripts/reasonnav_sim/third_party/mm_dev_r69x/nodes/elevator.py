import numpy as np
import rclpy
import time
from geometry_msgs.msg import PoseStamped, Pose, Transform, Polygon, Point32, TransformStamped
from std_msgs.msg import String, Float32MultiArray
from mm_dev.common.tf_utils import *
from mm_dev.common.vis_utils import xyyaw_to_marker
from mm_dev.nodes.vlm_nav import goToPose, DEFAULT_DET_QUERY, DEFAULT_DET_THRESH


def attempt_approach_pose(node, navigator, approach_pose):
    approach_x, approach_y, approach_yaw = pose_msg_to_xyyaw(approach_pose)
    approach_marker = xyyaw_to_marker(rclpy.time.Time(), "Approach", approach_x, approach_y, approach_yaw)
    node.goal_marker_pub.publish(approach_marker)

    nav_result = goToPose(navigator, approach_pose)
    return nav_result 


def elevator_primitive(node, navigator, next_landmark, target_floor, going_up):
    max_reposition_attempts = 3
    elevator_approach_dist = 1.5
    outerbutton_approach_dist = 1.0
    OUTER_BUTTON_QUERY = "a button"
    INNER_BUTTON_QUERY = "number %d" % target_floor

    while attempts <= max_reposition_attempts and OUTER_BUTTON_QUERY not in node.landmark_db:
        if attempts > 0:
            node.get_logger().info(f"find button retry attempt {attempts}")
            
        landmark_pose, elevdoor_approach_pose = node.get_landmark_approach_pose(next_landmark['name'], elevator_approach_dist)

        node.get_logger().info(f"Approaching {next_landmark['name']}")
        nav_result = attempt_approach_pose(node, navigator, elevdoor_approach_pose)
        if nav_result == False:
            attempts += 1
            continue

        node.get_logger().info("Pan Camera")
        node.pan_to_target(landmark_pose)
            
        # run detection on outer button
        outer_button_query = String()
        outer_button_query.data = OUTER_BUTTON_QUERY
        node.det_query_pub.publish(outer_button_query) 
        outer_button_thresh = Float32MultiArray()
        outer_button_thresh.data = [0.04]  ####################### TODO
        node.det_thresh_pub.publish(outer_button_thresh)
        # wait for detection
        time.sleep(2.0)
        t = 0
        while OUTER_BUTTON_QUERY not in node.landmark_db and t < 3:
            if t==0:
                node.pan_to_target(landmark_pose)
            if t==1:
                node.relative_pan("diag_left")
            if t==2:
                node.relative_pan("center")
                time.sleep(1.0)
                node.relative_pan("diag_right")
            t += 1
            time.sleep(2.0)
        if OUTER_BUTTON_QUERY not in node.landmark_db:
            continue
    # get outer button detections
    buttons_pos = np.array(node.landmark_db[OUTER_BUTTON_QUERY]['positions'])
    buttons_orientation = np.array(node.landmark_db[OUTER_BUTTON_QUERY]['orientations'])
    if going_up:
        button_idx = np.argmax(buttons_pos[:, 2])  # TODO: make sure most recent?
    else:
        button_idx = np.argmin(buttons_pos[:, 2])
    button_pose = Pose()
    button_pose.position.x = buttons_pos[button_idx][0]
    button_pose.position.y = buttons_pos[button_idx][1]
    button_pose.position.z = buttons_pos[button_idx][2]
    button_pose.orientation.x = buttons_orientation[button_idx][0]
    button_pose.orientation.y = buttons_orientation[button_idx][1]
    button_pose.orientation.z = buttons_orientation[button_idx][2]
    button_pose.orientation.w = buttons_orientation[button_idx][3]

    node.pan_to_target(button_pose)

    # move to outer button approach pose
    button_landmark_name = "Unvisited_button_%d" % button_idx

    landmark_pose, outerbutton_approach_pose = node.get_landmark_approach_pose(button_landmark_name, outerbutton_approach_dist)

    node.get_logger().info(f"Approaching {button_landmark_name}")
    nav_result = attempt_approach_pose(node, navigator, outerbutton_approach_pose)
    if nav_result == False:
        node.get_logger().info("Failed to go to outer button approach pose")
        return False

    # TODO: RUN BUTTON PRESS

    # go back to elevator door
    node.get_logger().info(f"Going back to elevator door")
    nav_result = attempt_approach_pose(node, navigator, elevdoor_approach_pose)
    if nav_result == False:
        node.get_logger().info("Failed to go back to elevator door")
        return False
    
    # TODO: WAIT FOR DOOR TO OPEN

    # TODO: GO TO INNER BUTTON PANEL

    # run detection on inner button
    inner_button_query = String()
    inner_button_query.data = INNER_BUTTON_QUERY
    node.det_query_pub.publish(inner_button_query) 
    inner_button_thresh = Float32MultiArray()
    inner_button_thresh.data = [0.04]  ####################### TODO
    node.det_thresh_pub.publish(inner_button_thresh)
    # wait for detection
    time.sleep(2.0)
    if INNER_BUTTON_QUERY not in node.landmark_db:
        node.get_logger().info("Failed to find inner button (number %d)" % target_floor)
        return False


    # TODO: RUN BUTTON PRESS

    # TODO: GO TO CENTER, WAIT FOR DOOR TO OPEN

    # TODO: RESET SLAM, GO OUTSIDE

    # change detection back to default query
    default_query = String()
    default_query.data = DEFAULT_DET_QUERY
    default_thresh = Float32MultiArray()
    default_thresh.data = DEFAULT_DET_THRESH
    node.det_query_pub.publish(default_query)
    node.det_thresh_pub.publish(default_thresh)

    return True



# move closer to room label
# roomlabel_approach_dist = 1.0
# roomlabel_landmark_name = "Unvisited_room label_%d" % (len(node.landmark_db['a room label']['positions']) - 1)

# landmark_pose, roomlabel_approach_pose = node.get_landmark_approach_pose(button_landmark_name, roomlabel_approach_dist)

# node.get_logger().info(f"Approaching {roomlabel_landmark_name}")
# nav_result = attempt_approach_pose(node, navigator, roomlabel_approach_pose)
# node.pan_to_target(label_pose)