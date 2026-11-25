#!/usr/bin/env python3

import rclpy
from rclpy.node import Node
from std_msgs.msg import String, Float32MultiArray
from sensor_msgs.msg import Image, CameraInfo
from vision_msgs.msg import Detection2D, Detection2DArray, ObjectHypothesisWithPose
from geometry_msgs.msg import PoseWithCovariance, Pose, Point, PoseStamped
from cv_bridge import CvBridge
from rclpy.qos import (qos_profile_sensor_data, QoSReliabilityPolicy, HistoryPolicy,
                       QoSProfile, DurabilityPolicy)
from realsense2_camera_msgs.msg import Extrinsics
from message_filters import ApproximateTimeSynchronizer, Subscriber
from tf2_ros import TransformListener, Buffer
from tf2_geometry_msgs import do_transform_pose
from tf2_msgs.msg import TFMessage
from geometry_msgs.msg import TransformStamped

from mm_dev.obj_det import ObjectDetector
from mm_dev.obj_det.detection import _BACKEND as DETECTOR_BACKEND

import numpy as np
from collections import deque

UPDATE_THRESHOLD = 1 # meters
REQUIRED_FRAMES = 6
HISTORY_SIZE = 20

class DetectorNode(Node):
    def __init__(self):
        super().__init__('nano_owl_node')
        
        # Declare parameters
        self.declare_parameter('model', 'google/owlvit-base-patch32')
        self.declare_parameter('image_encoder_engine', '/home/user/colcon_ws/data/owl_image_encoder_patch32.engine')
        self.declare_parameter('depth_units', 1) # 1 for isaac sim, 1000 for real world realsense
        # self.declare_parameter('threshold', 0.05)

        # Initialize detector
        model = self.get_parameter('model').get_parameter_value().string_value
        engine = self.get_parameter('image_encoder_engine').get_parameter_value().string_value
        self.depth_units = self.get_parameter('depth_units').get_parameter_value().integer_value
        self.detector = ObjectDetector(model_name=model, image_encoder_engine=engine)
        
        # Initialize CV bridge
        self.cv_bridge = CvBridge()
        
        # Set up QoS profile
        modified_qos = qos_profile_sensor_data
        modified_qos.depth = 1
        modified_qos.reliability = QoSReliabilityPolicy.BEST_EFFORT
        modified_qos.depth = 1
        modified_qos.history = HistoryPolicy.KEEP_LAST
        
        # Set up subscribers
        self.query_subscription = self.create_subscription(
            String,
            '/object_detector/input_query',
            self.query_callback,
            qos_profile=modified_qos
        )

        self.threshold_sub = self.create_subscription(
            Float32MultiArray,
            '/object_detector/threshold',
            self.threshold_callback,
            qos_profile=modified_qos
        )
            
        self.depth_info_sub = self.create_subscription(
            CameraInfo,
            '/camera/color/camera_info',
            self.camera_info_callback,
            qos_profile=modified_qos
        )

        # Raw-depth path: with the depth stream's own intrinsics and the
        # depth->colour extrinsics we can do the colour/depth correspondence
        # ourselves, which lets us consume /camera/depth/image_rect_raw (~30 Hz)
        # instead of the driver's CPU-aligned depth (~5-7 Hz).
        self.depth_cam_info_sub = self.create_subscription(
            CameraInfo,
            '/camera/depth/camera_info',
            self.depth_camera_info_callback,
            qos_profile=modified_qos
        )
        self.extrinsics_sub = self.create_subscription(
            Extrinsics,
            '/camera/extrinsics/depth_to_color',
            self.extrinsics_callback,
            qos_profile=QoSProfile(
                depth=1,
                reliability=QoSReliabilityPolicy.RELIABLE,
                durability=DurabilityPolicy.TRANSIENT_LOCAL,
                history=HistoryPolicy.KEEP_LAST,
            )
        )

        # Set up synchronized RGB and depth subscribers
        self.rgb_sub = Subscriber(self, Image, '/camera/color/image_raw', qos_profile=modified_qos)
        self.depth_sub = Subscriber(self, Image, '/camera/depth/image_rect_raw', qos_profile=modified_qos)
        
        # Create time synchronizer
        sync = ApproximateTimeSynchronizer([self.rgb_sub, self.depth_sub], 10, 0.1)
        sync.registerCallback(self.image_callback)

        # Set up publishers
        self.detection_pub = self.create_publisher(Detection2DArray, '/object_detector/output_detections', 10)
        self.image_pub = self.create_publisher(Image, '/object_detector/output_image', 10)
        self.tf_pub = self.create_publisher(TFMessage, '/tf', 10)

        # Set up TF listener
        self.tf_buffer = Buffer()
        self.tf_listener = TransformListener(self.tf_buffer, self)

        # Initialize state
        self.current_query = "a person, a door, a directional sign, a room label"  # default query "a door label, a room label"
        # Score scales differ per backend, so the default has to follow the
        # backend: OWL-ViT wants per-class values tuned low, while Grounding
        # DINO's usual operating point is a flat 0.25-0.35 and would miss most
        # doors at OWL-ViT's 0.4. vlm_nav overrides this once it starts.
        # YOLO is a plain sigmoid confidence and the README's operating point
        # is 0.35, with door recall weak enough that it wants a lower bar than
        # the other two classes.
        if DETECTOR_BACKEND.startswith('y'):
            # Order follows current_query: person, door, directional sign,
            # room label. The checkpoint's door recall is the weak spot (0.57 at
            # its default conf), so doors get the loose bar; directional_sign
            # was trained on 27 instances and is kept strict. room_label is the
            # strongest class here (mAP50 0.893) and is read continuously, so it
            # can afford a middling bar.
            self.current_threshold = [0.35, 0.25, 0.35, 0.30]
        elif DETECTOR_BACKEND.startswith('g'):
            self.current_threshold = [0.30, 0.30, 0.25, 0.25]
        else:
            self.current_threshold = [0.3, 0.4, 0.08, 0.06]
        # self.current_query = "a door"
        # self.current_threshold = [0.4]
        self.det_count = 0 # unique detection id
        self.detected = {} # make sure only add unique objs {tf_name : pose}
        # format: {label: {'names' : [], 'poses : [], 'positions': np.array([]), 'history': {}, 'confirmed': []}}

    def camera_info_callback(self, msg):
        """Handle camera info messages to set up intrinsics."""
        if not self.detector.has_intrinsics():
            self.detector.set_camera_intrinsics(
                width=msg.width,
                height=msg.height,
                ppx=msg.k[2],
                ppy=msg.k[5],
                fx=msg.k[0],
                fy=msg.k[4],
                distortion_model=msg.distortion_model,
                coeffs=[i for i in msg.d]
            )
            self.get_logger().info('Camera intrinsics set')

    def depth_camera_info_callback(self, msg):
        """Intrinsics of the raw depth stream."""
        if self.detector.depth_intrinsics is None:
            self.detector.set_depth_intrinsics(
                width=msg.width,
                height=msg.height,
                ppx=msg.k[2],
                ppy=msg.k[5],
                fx=msg.k[0],
                fy=msg.k[4],
                distortion_model=msg.distortion_model,
                coeffs=[i for i in msg.d]
            )
            self.get_logger().info('Depth intrinsics set')

    def extrinsics_callback(self, msg):
        """depth -> colour extrinsics; completes the raw-depth path."""
        if self.detector.depth_to_color is None:
            self.detector.set_depth_to_color_extrinsics(msg.rotation, msg.translation)
            self.get_logger().info(
                'depth->color extrinsics set; using raw depth for deprojection')

    def query_callback(self, msg):
        """Handle new query messages."""
        self.current_query = msg.data
        self.get_logger().info(f'Received new query: {self.current_query}')

    def threshold_callback(self, msg):
        """Handle new threshold messages."""
        self.current_threshold = msg.data
        self.get_logger().info(f'Received new threshold: {self.current_threshold}')

    def image_callback(self, rgb_msg:Image, depth_msg:Image):
        """Handle synchronized RGB and depth images."""
        if not self.detector.has_intrinsics():
            self.get_logger().warn('Waiting for camera intrinsics...')
            return

        try:
            # Convert ROS messages to OpenCV format
            rgb_image = self.cv_bridge.imgmsg_to_cv2(rgb_msg, 'rgb8')
            depth_image = self.cv_bridge.imgmsg_to_cv2(depth_msg, desired_encoding="passthrough")
            transform = self.tf_buffer.lookup_transform(
                        "map",
                        "realsense_link",
                        # rgb_msg.header.stamp,
                        rclpy.time.Time(),
                        rclpy.duration.Duration(seconds=1.0)
                    )
            # Run detection
            detections, vis_image = self.detector.detect_objects(
                rgb_image, 
                depth_image, 
                self.current_query,
                self.current_threshold,
                depth_units=self.depth_units # TODO FIX: depth units differ btwn isaac and real, make variable
            )

            # Create and publish Detection2DArray message
            detection_msg = Detection2DArray()
            detection_msg.header.stamp = rgb_msg.header.stamp
            detection_msg.header.frame_id = "map"

            for det in detections:
                try:
                    # Create pose in camera frame
                    pose_camera = PoseStamped()
                    pose_camera.header.frame_id = "realsense_link"
                    pose_camera.header.stamp = rgb_msg.header.stamp
                    pose_camera.pose.position.x = det['point_3d'][0]
                    pose_camera.pose.position.y = det['point_3d'][1]
                    pose_camera.pose.position.z = det['point_3d'][2]
                    pose_camera.pose.orientation.x = det['orientation'][0]
                    pose_camera.pose.orientation.y = det['orientation'][1]
                    pose_camera.pose.orientation.z = det['orientation'][2]
                    pose_camera.pose.orientation.w = det['orientation'][3]
                
                    world_pose = do_transform_pose(pose_camera.pose, transform)

                    # update existing detection instead if needed
                    curr_pos = np.array([
                        world_pose.position.x,
                        world_pose.position.y,
                        world_pose.position.z
                    ])
                    curr_label = det['label']

                    det_name, is_confirmed, median_pose = self.update_det(world_pose, curr_label, curr_pos)

                    # self.get_logger().info(f"{det_name}, {is_confirmed}, {len(self.detected[curr_label]['history'][det_name])}")

                    if is_confirmed:
                        # self.get_logger().info(f"Det Name {det_name}'s median pose: {median_pose}")
                        # Create Detection2D message
                        detection = Detection2D()
                        detection.header.stamp = rgb_msg.header.stamp
                        detection.header.frame_id = "map"
                        # float() on the way in: these fields assert on a
                        # non-float and abort the process rather than raising,
                        # and a numpy scalar or a clipped int reaches here
                        # depending on the detector backend.
                        detection.bbox.size_x = float(det['size_x'])
                        detection.bbox.size_y = float(det['size_y'])
                        detection.bbox.center.position.x = float(det['center_2d'][0])
                        detection.bbox.center.position.y = float(det['center_2d'][1])

                        # Add pose information
                        pose_with_cov = PoseWithCovariance()
                        pose_with_cov.pose = median_pose
                        
                        hyp = ObjectHypothesisWithPose()
                        hyp.pose = pose_with_cov
                        hyp.hypothesis.class_id = str(det['label'])
                        hyp.hypothesis.score = float(det['score'])
                        detection.results.append(hyp)
                        
                        detection_msg.detections.append(detection)

                        # Publish transform for visualization
                        self.publish_tf(median_pose, det_name)

                        bbox_corners_3d = det['bbox_corners_3d']
                        for i, corner in enumerate(bbox_corners_3d):
                            self.get_logger().debug(f"Corner {i}: {corner}")
                            corner_pose = Pose()
                            corner_pose.position.x = corner[0]                                                                                         
                            corner_pose.position.y = corner[1]
                            corner_pose.position.z = corner[2]
                            world_corner_pose = do_transform_pose(corner_pose, transform)
                            # corner_pose_with_cov = PoseWithCovariance()
                            # corner_pose_with_cov.pose = corner_pose.pose
                            self.publish_tf(world_corner_pose, curr_label + f"_corner_{i}")

                except Exception as e:
                    self.get_logger().error(f'Transform error for detection: {str(e)}')
                    continue

            # Publish detection array
            self.detection_pub.publish(detection_msg)

            # Publish visualization image
            vis_msg = self.cv_bridge.cv2_to_imgmsg(vis_image[:, :, ::-1], "bgr8")  # Convert RGB to BGR
            vis_msg.header = rgb_msg.header
            self.image_pub.publish(vis_msg)

        except Exception as e:
            self.get_logger().error(f'Error processing images: {str(e)}')

    def publish_tf(self, world_pose, label_index):
        """Publish transform for visualization."""
        transform = TransformStamped()
        transform.header.stamp = self.get_clock().now().to_msg()
        transform.header.frame_id = "map"
        transform.child_frame_id = f"object_{label_index}"
        
        transform.transform.translation.x = world_pose.position.x
        transform.transform.translation.y = world_pose.position.y
        transform.transform.translation.z = world_pose.position.z
        transform.transform.rotation = world_pose.orientation
        
        # tf_message = TFMessage(transforms=[transform])
        # self.tf_pub.publish(tf_message)


    def update_det(self, world_pose, curr_label, curr_pos):
        if curr_label not in self.detected:
            self.detected[curr_label] = {
                'names': [],
                'poses': [],
                'positions': np.empty((0,3)),
                'history': {},
                'confirmed': []
            }
        
        det_name = None
        is_confirmed = False
        median_pose = world_pose

        existing_pos = self.detected[curr_label]['positions']
        if len(existing_pos)>0:
            dist = np.linalg.norm(existing_pos - curr_pos, axis=1)
            # dist = np.linalg.norm(existing_pos[:,:,2] - curr_pos[:,:,2], axis=1)
            min_idx = np.argmin(dist)
            min_dist = dist[min_idx]

            if min_dist < UPDATE_THRESHOLD:
                det_name = self.detected[curr_label]['names'][min_idx]

                if det_name not in self.detected[curr_label]['history']:
                    self.detected[curr_label]['history'][det_name] = deque(maxlen=HISTORY_SIZE)
                history = self.detected[curr_label]['history'][det_name]
                history.append(world_pose)

                # if enough detections to confirm object
                if len(history) >= REQUIRED_FRAMES:
                    if det_name not in self.detected[curr_label]['confirmed']:
                        self.detected[curr_label]['confirmed'].append(det_name)
                        # self.get_logger().info(f"Detected object {det_name} with {len(history)} observations")

                    median_pose = self.compute_median_pose(history)
                    is_confirmed = True

                    self.detected[curr_label]['poses'][min_idx] = median_pose
                    self.detected[curr_label]['positions'][min_idx] = np.array([
                        median_pose.position.x,
                        median_pose.position.y,
                        median_pose.position.z
                    ])
                else:
                    self.detected[curr_label]['poses'][min_idx] = world_pose
                    self.detected[curr_label]['positions'][min_idx] = curr_pos

        if det_name == None: # new detection
            det_name = f"{curr_label}_{self.det_count}"
            self.det_count += 1

            # add to existing detections
            self.detected[curr_label]['names'].append(det_name)
            self.detected[curr_label]['poses'].append(world_pose)
            positions = self.detected[curr_label]['positions']
            self.detected[curr_label]['positions'] = np.vstack([positions, curr_pos])
            self.detected[curr_label]['history'][det_name] = deque(maxlen=HISTORY_SIZE)
            self.detected[curr_label]['history'][det_name].append(world_pose)

        return det_name, is_confirmed, median_pose

    def compute_median_pose(self, pose_history):
        median_pose = Pose()

        positions = np.array([
            [p.position.x, p.position.y, p.position.z] for p in pose_history
        ])
        median_pos = np.median(positions, axis=0)
        median_pose.position.x = float(median_pos[0])
        median_pose.position.y = float(median_pos[1])
        median_pose.position.z = float(median_pos[2])

        orientations = np.array([
            [p.orientation.x, p.orientation.y, p.orientation.z, p.orientation.w] for p in pose_history
        ])
        median_orientation = orientations[-1]
        median_pose.orientation.x = float(median_orientation[0])
        median_pose.orientation.y = float(median_orientation[1])
        median_pose.orientation.z = float(median_orientation[2])
        median_pose.orientation.w = float(median_orientation[3])

        return median_pose



def main(args=None):
    rclpy.init(args=args)
    node = DetectorNode()
    
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
        
    node.destroy_node()
    rclpy.shutdown()


if __name__ == '__main__':
    main()