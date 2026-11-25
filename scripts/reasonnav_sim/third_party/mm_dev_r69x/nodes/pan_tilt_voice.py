#!/usr/bin/env python3
import rclpy
from rclpy.node import Node

from sensor_msgs.msg import Joy
from geometry_msgs.msg import Twist, TwistStamped
from control_msgs.msg import JointJog
from std_msgs.msg import String, Int32
from std_srvs.srv import Trigger
from trajectory_msgs.msg import JointTrajectory, JointTrajectoryPoint
import time
from enum import Enum
from speech_recognition_msgs.msg import SpeechRecognitionCandidates

class PanTiltVoice(Node):
    def __init__(self):
        super().__init__("pan_tilt_voice_follow")
        self.get_logger().info(f"Started pan_tilt_voice_follow node")

        self.subscription = self.create_subscription(
            SpeechRecognitionCandidates,
            '/speech_to_text',
            self.listener_callback,
            10)
        self.subscription  # prevent unused variable warning
        self.pt_publisher = self.create_publisher(JointTrajectory, '/pan_tilt_position_controller/joint_trajectory', 10)
        
    def listener_callback(self, msg: SpeechRecognitionCandidates):
        transcript = " ".join(msg.transcript)
        # "robot" and "left" are the keywords, move pan tilt left, same for center and right
        if not transcript:
            self.get_logger().info("No speech detected.")
            return
        self.get_logger().info(f"Transcript: {transcript}")
        # Check for keywords in the transcript
        if "robot" not in transcript.lower():
            self.get_logger().info("No command for robot found in transcript.")
            return
        
        if "left" in transcript.lower():
            self.get_logger().info("Moving pan tilt to left.")
            traj = JointTrajectory()
            traj.joint_names = ["tilt_joint", "pan_joint"]
            point = JointTrajectoryPoint()
            point.positions = [0.0, -float(1.57)]
            traj.points.append(point)
            self.pt_publisher.publish(traj)
        elif "forward" in transcript.lower() or "straight" in transcript.lower() or "center" in transcript.lower():
            self.get_logger().info("Moving pan tilt to center.")
            traj = JointTrajectory()
            traj.joint_names = ["tilt_joint", "pan_joint"]
            point = JointTrajectoryPoint()
            point.positions = [0.0, float(0.0)]
            traj.points.append(point)
            self.pt_publisher.publish(traj)
        elif "right" in transcript.lower():
            self.get_logger().info("Moving pan tilt to right.")
            traj = JointTrajectory()
            traj.joint_names = ["tilt_joint", "pan_joint"]
            point = JointTrajectoryPoint()
            point.positions = [0.0, float(1.57)]
            traj.points.append(point)
            self.pt_publisher.publish(traj)
        elif "down" in transcript.lower():
            self.get_logger().info("Moving pan tilt to down.")
            traj = JointTrajectory()
            traj.joint_names = ["tilt_joint", "pan_joint"]
            point = JointTrajectoryPoint()
            point.positions = [-1.0, 0.0]
            traj.points.append(point)
            self.pt_publisher.publish(traj)
        # pan 0 deg --> 90 deg voice
        # pan 90 deg --> 180 or -180 deg voice
        # # pan -90 deg --> 0 deg voice
        # voice_deg = msg.data - 90
        # voice_rad = voice_deg * 3.14159 / 180
        # self.get_logger().info(f"Received sound direction: {msg.data}")
        # self.get_logger().info(f"Voice angle in rad: {float(voice_rad)}")
        # traj = JointTrajectory()
        # traj.joint_names = ["tilt_joint", "pan_joint"]
        # point = JointTrajectoryPoint()
        # point.positions = [0.0, float(voice_rad)]
        # traj.points.append(point)
        # self.pt_publisher.publish(traj)

def main(args=None):
    rclpy.init(args=args)

    teleop = PanTiltVoice()

    try:
        rclpy.spin(teleop)
    except KeyboardInterrupt:
        pass

    teleop.destroy_node()
    rclpy.try_shutdown()


if __name__ == '__main__':
    main()
