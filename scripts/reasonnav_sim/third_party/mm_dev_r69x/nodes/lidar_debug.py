#!/usr/bin/env python3
import rclpy
from rclpy.node import Node

from std_msgs.msg import String
from sensor_msgs.msg import Image, JointState
from cv_bridge import CvBridge

import cv2
import numpy as np

class LidarDebug(Node):
    def __init__(self):
        super().__init__("lidar_debug_node")
        self.scan_sub = self.create_subscription(
            LaserScan,
            '/scan',
            self.scan_callback,
            qos_profile=10)

        self.scan_filtered_sub = self.create_subscription(
            LaserScan,
            '/scan_filtered',
            self.scan_filtered_callback,
            qos_profile=10)

        self.tf_sub = self.create_subscription(
            String,
            '/tf',
            self.tf_callback,
            qos_profile=10)

    def scan_callback(self, msg):
        time = msg.header.stamp
        self.get_logger().info(f"scan time: {time.seconds + time.nanoseconds*1e-9}")
        print(f"scan time: {time.seconds + time.nanoseconds*1e-9}")

    def scan_filtered_callback(self, msg):
        time = msg.header.stamp
        self.get_logger().info(f"scan_filtered time: {time.seconds + time.nanoseconds*1e-9}")
        print(f"scan_filtered time: {time.seconds + time.nanoseconds*1e-9}")

    def tf_callback(self, msg):
        # time = msg.header.stamp
        # self.get_logger().info(f"\scan time: {time.seconds + time.nanoseconds*1e-9}")
        return

def main(args=None):
    rclpy.init(args=args)

    node = LidarDebug()

    try:
        rclpy.spin(node)

    except KeyboardInterrupt:
        pass

    node.destroy_node()
    rclpy.try_shutdown()


if __name__ == '__main__':
    main()