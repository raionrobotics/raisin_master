#!/usr/bin/env python3
"""Relay a bag's /tf_static minus the transforms that must not come from a bag.

A recorded /tf_static carries whatever static publishers were alive at record
time -- including, in the 2026-09-08 bags, an identity map -> base_link that
some tool published a couple of seconds after the body -> base_link bridge. In
tf2 the last parent set wins, so on replay base_link was re-parented onto map
at the origin: every node saw the rig standing at (0, 0) for the whole bag
while the detections (looked up through realsense_link -> body) moved normally.

The realsense_* frames in the same messages are needed (no driver runs in
replay), so the bag's /tf_static is remapped to /tf_static_bag and this node
forwards everything except transforms whose child is one of the frames the
replay launch already bridges itself.
"""
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, DurabilityPolicy, ReliabilityPolicy, HistoryPolicy
from tf2_msgs.msg import TFMessage

BRIDGED_CHILDREN = {'base_link', 'odom', 'camera_init', 'body', 'realsense_link'}


class TfStaticFilter(Node):
    def __init__(self):
        super().__init__('tf_static_filter')
        qos = QoSProfile(depth=100, durability=DurabilityPolicy.TRANSIENT_LOCAL,
                         reliability=ReliabilityPolicy.RELIABLE,
                         history=HistoryPolicy.KEEP_ALL)
        self.pub = self.create_publisher(TFMessage, '/tf_static', qos)
        self.sub = self.create_subscription(TFMessage, '/tf_static_bag', self.on_tf, qos)
        self.seen = set()

    def on_tf(self, msg: TFMessage):
        keep, dropped = [], []
        for tr in msg.transforms:
            if tr.child_frame_id in BRIDGED_CHILDREN:
                dropped.append(f'{tr.header.frame_id}->{tr.child_frame_id}')
                continue
            keep.append(tr)
        if dropped:
            self.get_logger().info('dropped from bag /tf_static: ' + ', '.join(dropped))
        if keep:
            out = TFMessage(); out.transforms = keep
            self.pub.publish(out)


def main():
    rclpy.init()
    n = TfStaticFilter()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
