#!/usr/bin/env python3
import rclpy
from rclpy.node import Node

from sensor_msgs.msg import Joy
from geometry_msgs.msg import Twist, TwistStamped
from control_msgs.msg import JointJog
from std_msgs.msg import String
from std_srvs.srv import Trigger
from xarm_msgs.srv import SetInt16, SetFloat32, GripperMove
import time
from enum import Enum

class Control_Mode(Enum):
    BASE = 1
    ARM = 2
class btns(Enum):
    A = 0
    B = 1
    X = 2
    Y = 3
    LB = 4
    RB = 5
    L_CIRC = 6
    R_CIRC = 7
    HOME = 8
    L_JOY_PRESS = 9
    R_JOY_PRESS = 10
    M_CIRC = 11

class axes(Enum):
    L_JOYX = 0
    L_JOYY = 1
    LT = 2 # (unpressed =1, fully pressed = -1)
    R_JOYX = 3
    R_JOYY = 4
    RT = 5
    DPAD_LR = 6 # (left is 1 right is -1)
    DPAD_UD = 7 # (up is 1 down is -1)
#xbox one button mappings
# AxesFloat32Array(8)[]
# {0: LeftJoyX
#  1: leftJoyY
#  2: Left Trigger(unpressed =1, fully pressed = -1)
#  3: RightJoyX
#  4: RightJoyY
#  5: Right trigger
#  6: D-pad button(left is 1 right is -1)
#  7: D-pad button(up down)
#  }
# buttons Int32Array(12)[A, B, X, Y, LB, RB, left_small, right_small, xbox home, left joy press, right joy press, center_small]
LIN_VEL_SCALE = 0.7
ANG_VEL_SCALE = 0.4

class Teleop(Node):
    def __init__(self):
        super().__init__("teleop")
        example_param = self.declare_parameter("example_param", "default_value").value
        self.get_logger().info(f"Declared parameter 'example_param'. Value: {example_param}")

        self.cmd_vel_pub = self.create_publisher(Twist, '/cmd_vel', 10)
        self.xarm_twist_pub = self.create_publisher(TwistStamped, '/servo_server/delta_twist_cmds', 10)
        self.xarm_jog_pub = self.create_publisher(JointJog, '/servo_server/delta_joint_cmds', 10)
        self.control_mode = Control_Mode.ARM
        self.control_mode_pub = self.create_publisher(String, 'teleop_control_mode', 10)
        self.mode_button_state = 0
        self.servo_start_client = self.create_client(Trigger, "/servo_server/start_servo")
        while not self.servo_start_client.wait_for_service(1.0):
            self.get_logger().info('waiting for xarm servo start service...')
        req = Trigger.Request()
        self.servo_req_future = self.servo_start_client.call_async(req)
        rclpy.spin_until_future_complete(self, self.servo_req_future)
        # setup gripper control
        # $ ros2 service call /xarm/set_gripper_mode xarm_msgs/srv/SetInt16 "data: 0"
        self.set_gripper_mode = self.create_client(SetInt16, "/xarm/set_gripper_mode")
        while not self.set_gripper_mode.wait_for_service(1.0):
            self.get_logger().info('waiting for xarm set_gripper_mode start service...')
        req = SetInt16.Request()
        req.data = 0
        self.set_gripper_mode_req_future = self.set_gripper_mode.call_async(req)
        rclpy.spin_until_future_complete(self, self.set_gripper_mode_req_future)
        # $ ros2 service call /xarm/set_gripper_enable xarm_msgs/srv/SetInt16 "data: 1"
        self.set_gripper_enable = self.create_client(SetInt16, "/xarm/set_gripper_enable")
        while not self.set_gripper_enable.wait_for_service(1.0):
            self.get_logger().info('waiting for xarm set_gripper_enable start service...')
        req = SetInt16.Request()
        req.data = 1
        self.set_gripper_enable_req_future = self.set_gripper_enable.call_async(req)
        rclpy.spin_until_future_complete(self, self.set_gripper_enable_req_future)
        # $ ros2 service call /xarm/set_gripper_speed xarm_msgs/srv/SetFloat32 "data: 3000"
        self.set_gripper_speed = self.create_client(SetFloat32, "/xarm/set_gripper_speed")
        while not self.set_gripper_speed.wait_for_service(1.0):
            self.get_logger().info('waiting for xarm set_gripper_speed start service...')
        req = SetFloat32.Request(data=3000.0)
        # req.data = 3000.0
        self.set_gripper_speed_req_future = self.set_gripper_speed.call_async(req)
        rclpy.spin_until_future_complete(self, self.set_gripper_speed_req_future)
        # $ ros2 service call /xarm/set_gripper_position xarm_msgs/srv/GripperMove "{pos: 200, wait: false, timeout: 10.0}"
        self.set_gripper_position = self.create_client(GripperMove, "/xarm/set_gripper_position")
        while not self.set_gripper_position.wait_for_service(1.0):
            self.get_logger().info('waiting for xarm set_gripper_position start service...')
        self.cur_gripper_position = 850
        self.command_gripper()
        self.subscription = self.create_subscription(
            Joy,
            '/joy',
            self.listener_callback,
            10)
        self.subscription  # prevent unused variable warning
    def command_gripper(self):
        if self.cur_gripper_position < 0:
            self.cur_gripper_position = 0
        if self.cur_gripper_position > 850:
            self.cur_gripper_position = 850
        req = GripperMove.Request()
        req.pos = float(self.cur_gripper_position)
        req.timeout = 10.0
        set_gripper_position_req_future = self.set_gripper_position.call_async(req)
        # self.get_logger().info('waiting for gripper...')
        # rclpy.spin_until_future_complete(self, set_gripper_position_req_future)
    def listener_callback(self, msg: Joy):
        # Check Mode
        if msg.buttons[btns.HOME.value] == 1 and self.mode_button_state == 0:
            mode_msg = String()
            if self.control_mode == Control_Mode.ARM:
                self.control_mode = Control_Mode.BASE
                mode_msg.data = "Base"
            else:
                self.control_mode = Control_Mode.ARM
                mode_msg.data = "Arm"

            self.control_mode_pub.publish(mode_msg)
        self.mode_button_state = msg.buttons[8]
        if self.control_mode == Control_Mode.ARM:
            self.cmd_vel_pub.publish(Twist()) # make sure base won't move
            # gripper control
            if (msg.buttons[btns.L_CIRC.value]):
                self.cur_gripper_position +=50
                self.get_logger().info(f"Gripper Opening:{self.cur_gripper_position}")
                self.command_gripper()
            elif (msg.buttons[btns.R_CIRC.value]):
                self.cur_gripper_position -= 50
                self.get_logger().info(f"Gripper Closing:{self.cur_gripper_position}")
                self.command_gripper()
            # joint jog
            if (msg.buttons[btns.A.value] or msg.buttons[btns.B.value] or \
                msg.buttons[btns.X.value] or msg.buttons[btns.Y.value] or \
                msg.axes[axes.DPAD_LR.value] or msg.axes[axes.DPAD_UD.value]):
                print("JOINT JOGGING")
                joint_msg = JointJog()
                joint_msg.header.frame_id = "joint"
                joint_msg.header.stamp = self.get_clock().now().to_msg()

                joint_names = ["joint1", "joint2", "joint6", "joint7"]
                velocities = [msg.axes[axes.DPAD_LR.value],
                              msg.axes[axes.DPAD_UD.value],
                              msg.buttons[btns.B.value] - msg.buttons[btns.X.value],
                              2*(msg.buttons[btns.Y.value] - msg.buttons[btns.A.value])
                            ]

                velocities = [2.0*float(i) for i in velocities]
                joint_msg.joint_names = joint_names
                joint_msg.velocities = velocities
                self.xarm_jog_pub.publish(joint_msg)
            else:
                # end-effector control
                ee_twist = TwistStamped()
                ee_twist.header.frame_id = "link_base"
                ee_twist.header.stamp = self.get_clock().now().to_msg()
                mult = 1.5
                ee_twist.twist.linear.x = mult*msg.axes[axes.L_JOYY.value]
                ee_twist.twist.linear.y = mult*msg.axes[axes.L_JOYX.value]
                ee_twist.twist.linear.z = mult*-1*(msg.axes[axes.LT.value] - msg.axes[axes.RT.value])
                ee_twist.twist.angular.y = mult*msg.axes[axes.R_JOYY.value]
                ee_twist.twist.angular.x = mult*msg.axes[axes.R_JOYX.value]
                ee_twist.twist.angular.z = mult*float(msg.buttons[btns.LB.value] - msg.buttons[btns.RB.value])
                
                self.xarm_twist_pub.publish(ee_twist)


        if self.control_mode == Control_Mode.BASE:
            base_twist = Twist()
            # base_twist.header.frame_id = "base_link"
            # base_twist.header.stamp = self.get_clock().now().to_msg()
            base_twist.linear.x = msg.axes[axes.L_JOYY.value] * LIN_VEL_SCALE
            base_twist.linear.y = msg.axes[axes.L_JOYX.value] * LIN_VEL_SCALE
            base_twist.linear.z = 0.0
            base_twist.angular.y = 0.0
            base_twist.angular.x = 0.0
            base_twist.angular.z = msg.axes[axes.R_JOYX.value] * ANG_VEL_SCALE
            if base_twist.linear.x < 0:
                base_twist.angular.z *= -1
            self.cmd_vel_pub.publish(base_twist)

            #             double getVal(
            #   const sensor_msgs::msg::Joy::SharedPtr joy_msg, const std::map<std::string, int64_t> & axis_map,
            #   const std::map<std::string, double> & scale_map, const std::string & fieldname)
            # {
            #   if (axis_map.find(fieldname) == axis_map.end() ||
            #     axis_map.at(fieldname) == -1L ||
            #     scale_map.find(fieldname) == scale_map.end() ||
            #     static_cast<int>(joy_msg->axes.size()) <= axis_map.at(fieldname))
            #   {
            #     return 0.0;
            #   }

            #   return joy_msg->axes[axis_map.at(fieldname)] * scale_map.at(fieldname);
            # }

            # void TeleopTwistJoy::Impl::sendCmdVelMsg(
            #   const sensor_msgs::msg::Joy::SharedPtr joy_msg,
            #   const std::string & which_map)
            # {
            #   if (publish_stamped_twist) {
            #     auto cmd_vel_stamped_msg = std::make_unique<geometry_msgs::msg::TwistStamped>();
            #     cmd_vel_stamped_msg->header.stamp = clock->now();
            #     cmd_vel_stamped_msg->header.frame_id = frame_id;
            #     fillCmdVelMsg(joy_msg, which_map, &cmd_vel_stamped_msg->twist);
            #     cmd_vel_stamped_pub->publish(std::move(cmd_vel_stamped_msg));
            #   } else {
            #     auto cmd_vel_msg = std::make_unique<geometry_msgs::msg::Twist>();
            #     fillCmdVelMsg(joy_msg, which_map, cmd_vel_msg.get());
            #     cmd_vel_pub->publish(std::move(cmd_vel_msg));
            #   }
            #   sent_disable_msg = false;
            # }

            # void TeleopTwistJoy::Impl::fillCmdVelMsg(
            #   const sensor_msgs::msg::Joy::SharedPtr joy_msg,
            #   const std::string & which_map,
            #   geometry_msgs::msg::Twist * cmd_vel_msg)
            # {
            #   double lin_x = getVal(joy_msg, axis_linear_map, scale_linear_map[which_map], "x");
            #   double ang_z = getVal(joy_msg, axis_angular_map, scale_angular_map[which_map], "yaw");

            #   cmd_vel_msg->linear.x = lin_x;
            #   cmd_vel_msg->linear.y = getVal(joy_msg, axis_linear_map, scale_linear_map[which_map], "y");
            #   cmd_vel_msg->linear.z = getVal(joy_msg, axis_linear_map, scale_linear_map[which_map], "z");
            #   cmd_vel_msg->angular.z = (lin_x < 0.0 && inverted_reverse) ? -ang_z : ang_z;
            #   cmd_vel_msg->angular.y = getVal(joy_msg, axis_angular_map, scale_angular_map[which_map], "pitch");
            #   cmd_vel_msg->angular.x = getVal(joy_msg, axis_angular_map, scale_angular_map[which_map], "roll");
            # }

def main(args=None):
    rclpy.init(args=args)

    teleop = Teleop()

    try:
        rclpy.spin(teleop)
    except KeyboardInterrupt:
        pass

    teleop.destroy_node()
    rclpy.try_shutdown()


if __name__ == '__main__':
    main()
