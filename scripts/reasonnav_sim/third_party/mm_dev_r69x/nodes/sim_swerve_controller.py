#!/usr/bin/python3
import math
import threading
import rclpy
import numpy as np
from rclpy.node import Node
from std_msgs.msg import Float64MultiArray
from geometry_msgs.msg import Twist
from sensor_msgs.msg import Joy
from enum import Enum

vel_msg = Twist()  # robot velosity
msg_vel = Twist()
mode_selection = 0 # 1:opposite phase, 2:in-phase, 3:pivot turn 4: none

class Commander(Node):

    def __init__(self):
        super().__init__('commander')
        timer_period = 0.02
        self.wheel_seperation = 0.494
        self.wheel_base = 0.364
        self.wheel_radius = 0.1
        self.wheel_steering_y_offset = 0.05
        self.steering_track = self.wheel_seperation - 2*self.wheel_steering_y_offset

        self.pos = np.array([0,0,0,0], float)
        self.vel = np.array([0,0,0,0], float) #left_front, right_front, left_rear, right_rear

        self.pub_pos = self.create_publisher(Float64MultiArray, '/forward_position_controller/commands', 10)
        self.pub_vel = self.create_publisher(Float64MultiArray, '/forward_velocity_controller/commands', 10)
        self.timer = self.create_timer(timer_period, self.timer_callback)

    def timer_callback(self):
        global vel_msg, mode_selection, msg_vel
        vel_msg = msg_vel
        # opposite phase, ackermann
        if(mode_selection == 1):
            
            vel_steerring_offset = vel_msg.angular.z * self.wheel_steering_y_offset
            sign = np.sign(vel_msg.linear.x)

            self.vel[0] = sign*math.hypot(vel_msg.linear.x - vel_msg.angular.z*self.steering_track/2, vel_msg.angular.z*self.wheel_base/2) - vel_steerring_offset
            self.vel[1] = sign*math.hypot(vel_msg.linear.x + vel_msg.angular.z*self.steering_track/2, vel_msg.angular.z*self.wheel_base/2) + vel_steerring_offset
            self.vel[2] = sign*math.hypot(vel_msg.linear.x - vel_msg.angular.z*self.steering_track/2, vel_msg.angular.z*self.wheel_base/2) - vel_steerring_offset
            self.vel[3] = sign*math.hypot(vel_msg.linear.x + vel_msg.angular.z*self.steering_track/2, vel_msg.angular.z*self.wheel_base/2) + vel_steerring_offset
            # for i in range(len(self.vel)):
            #     self.vel[i] *= 3.0
            self.pos[0] = math.atan(vel_msg.angular.z*self.wheel_base/(2*vel_msg.linear.x + vel_msg.angular.z*self.steering_track))
            self.pos[1] = math.atan(vel_msg.angular.z*self.wheel_base/(2*vel_msg.linear.x - vel_msg.angular.z*self.steering_track))
            self.pos[2] = -self.pos[0]
            self.pos[3] = -self.pos[1]

        # in-phase, swerve
        elif(mode_selection == 2):

            V = math.hypot(vel_msg.linear.x, vel_msg.linear.y)
            sign = np.sign(vel_msg.linear.x)
            
            if(vel_msg.linear.x != 0):
                ang = vel_msg.linear.y / vel_msg.linear.x
                self.pos[0] = math.atan(ang)
                self.pos[1] = math.atan(ang)
                self.pos[2] = self.pos[0]
                self.pos[3] = self.pos[1]
            else: # only y velocity
                ang = math.pi/2
                sign = np.sign(vel_msg.linear.y)
                self.pos[0] = ang
                self.pos[1] = ang
                self.pos[2] = ang
                self.pos[3] = ang
            self.vel[:] = sign*V
            
        # pivot turn
        elif(mode_selection == 3):

            self.pos[0] = -math.atan(self.wheel_base/self.steering_track)
            self.pos[1] = math.atan(self.wheel_base/self.steering_track)
            self.pos[2] = math.atan(self.wheel_base/self.steering_track)
            self.pos[3] = -math.atan(self.wheel_base/self.steering_track)

            # Calculate linear speed based on distance from center
            rotation_radius = math.hypot(self.steering_track / 2.0, self.wheel_base / 2.0)
            wheel_linear_speed = vel_msg.angular.z * rotation_radius

            self.vel[0] = -wheel_linear_speed
            self.vel[1] = wheel_linear_speed
            # Assuming rear wheels mirror front during pivot:
            self.vel[2] = -wheel_linear_speed
            self.vel[3] = wheel_linear_speed
            # for i in range(len(self.vel)):
            #     self.vel[i] *= 2.0
        else:
            self.pos[:] = 0
            self.vel[:] = 0
        # print mode
        # self.get_logger().info('mode: "%s"' % str(mode_selection))
        # self.get_logger().info('pos: "%s"' % str(self.pos))

        # Check if radius is valid before division
        if self.wheel_radius <= 0:
            self.get_logger().error("Wheel radius is invalid (<= 0). Cannot calculate angular velocity. Setting velocity to 0.")
            # Create an array of zeros for velocity
            final_vel_data = np.zeros_like(self.vel)
        else:
            # Convert calculated linear wheel velocity (self.vel, in m/s)
            # to angular velocity (rad/s) expected by the controller.
            angular_vel_data = self.vel / self.wheel_radius
            final_vel_data = angular_vel_data

        pos_array = Float64MultiArray(data=self.pos)
        # Publish the calculated angular velocities
        vel_array = Float64MultiArray(data=final_vel_data)

        # pos_array = Float64MultiArray(data=self.pos) 
        # vel_array = Float64MultiArray(data=self.vel) 
        self.pub_pos.publish(pos_array)
        self.pub_vel.publish(vel_array)
        self.pos[:] = 0
        self.vel[:] = 0
class Joy_subscriber(Node):

    def __init__(self):
        super().__init__('joy_subscriber')
        self.subscription = self.create_subscription(
            Joy,
            'joy',
            self.listener_callback,
            10)
        self.subscription

    def listener_callback(self, data):
        global vel_msg, mode_selection

        if(data.buttons[0] == 1):   # in-phase # A button of Xbox 360 controller
            mode_selection = 2
        elif(data.buttons[4] == 1): # opposite phase # LB button of Xbox 360 controller
            mode_selection = 1
        elif(data.buttons[5] == 1): # pivot turn # RB button of Xbox 360 controller
            mode_selection = 3
        else:
            mode_selection = 4

        vel_msg.linear.x = data.axes[1]*7.5
        vel_msg.linear.y = data.axes[0]*7.5
        vel_msg.angular.z = data.axes[3]*10
class MotionState(Enum):
    MOTION_MODE_DUAL_ACKERMAN = 1
    MOTION_MODE_PARALLEL = 2
    MOTION_MODE_SPINNING = 3
    MOTION_MODE_SIDE_SLIP = 4
class Teleop_sub(Node):
    def __init__(self):
        super().__init__('teleop_sub')
        self.subscription = self.create_subscription(Twist,'cmd_vel',self.cmd_callback,10)
        self.subscription
        self.robot_params =  {
            "track": 0.364,  # in meter (left & right wheel distance)
            "wheelbase": 0.494,  # in meter (front & rear wheel distance)
            "max_linear_speed": 1.5,  # in m/s
            "max_angular_speed": 4.8,  # in rad/s
            "max_speed_cmd": 10.0,  # in rad/s
            "max_steer_angle_central": 0.4782,  # ~= 27.40 degree
            "max_steer_angle_parallel": 1.570,  # 180 degree
            "max_round_angle": 0.935671,
            "min_turn_radius": 0.4#0.4764
        }
        self.motion_mode = 'MOTION_MODE_DUAL_ACKERMAN'
 
    def calculate_steering_angle(self, msg: Twist, radius: float) -> float:
        linear = abs(msg.linear.x)
        angular = abs(msg.angular.z)

        # Circular motion
        radius = linear / angular
        k = 1.0 if (msg.angular.z * msg.linear.x) >= 0 else -1.0

        l = self.robot_params['wheelbase']
        w = self.robot_params['track']
        x = math.sqrt(radius * radius + (l / 2) * (l / 2))
        phi_i = math.atan((l / 2) / radius)
        return k * phi_i

    def convert_inner_angle_to_central(self, angle: float) -> float:
        phi_i = abs(angle)

        phi = math.atan(self.robot_params['wheelbase'] * math.sin(phi_i) /
                        (self.robot_params['wheelbase'] * math.cos(phi_i) +
                         self.robot_params['track'] * math.sin(phi_i)))

        phi *= 1.0 if angle >= 0 else -1.0
        return phi

    def convert_central_angle_to_inner(self, angle: float) -> float:
        phi = abs(angle)

        phi_i = math.atan(self.robot_params['wheelbase'] * math.sin(phi) /
                          (self.robot_params['wheelbase'] * math.cos(phi) -
                           self.robot_params['track'] * math.sin(phi)))
        phi_i *= 1.0 if angle >= 0 else -1.0
        return phi_i
    def cmd_callback(self,msg:Twist):
        global msg_vel, mode_selection
        steer_cmd = 0.0
        radius = abs(msg.linear.x) / abs(msg.angular.z) if msg.angular.z != 0 else 1000.0
        tolerance = 0.05
        # # Analyze Twist msg and switch motion_mode
        if abs(msg.linear.x) < tolerance and abs(msg.linear.y) < tolerance and abs(msg.angular.z) < tolerance:
            self.motion_mode = 'STOPPING'
            mode_selection = 4
        elif abs(msg.linear.y) > tolerance:
            # if msg.linear.x == 0.0 and self.robot_type == 'kRangerMiniV1':
            #     self.motion_mode = 'MOTION_MODE_SIDE_SLIP'
            # else:
            self.motion_mode = 'MOTION_MODE_PARALLEL'
            mode_selection = 2
        else:
            # steer_cmd = self.calculate_steering_angle(msg, radius)
            # Use minimum turn radius to switch between dual ackerman and spinning mode
            self.get_logger().info('radius: "%s"' % str(radius))
            if radius < self.robot_params['min_turn_radius']: #abs(msg.linear.x) < tolerance: #
                if abs(msg.angular.z) < tolerance:
                    self.motion_mode = 'STOPPING'
                    mode_selection = 4
                else:
                    self.motion_mode = 'MOTION_MODE_SPINNING'
                    mode_selection = 3
            else:
                self.motion_mode = 'MOTION_MODE_DUAL_ACKERMAN'
                mode_selection = 1
        # # Send motion command to robot
        # if self.motion_mode == 'MOTION_MODE_DUAL_ACKERMAN':
        #     if steer_cmd > self.robot_params['max_steer_angle_central']:
        #         steer_cmd = self.robot_params['max_steer_angle_central']
        #     if steer_cmd < -self.robot_params['max_steer_angle_central']:
        #         steer_cmd = -self.robot_params['max_steer_angle_central']
        #     phi_i = self.convert_central_angle_to_inner(steer_cmd)
        #     self.set_motion_command(msg.linear.x, phi_i)
        # elif self.motion_mode == 'MOTION_MODE_PARALLEL':
        #     steer_cmd = math.atan(msg.linear.y / msg.linear.x)
        #     if steer_cmd > self.robot_params['max_steer_angle_parallel']:
        #         steer_cmd = self.robot_params['max_steer_angle_parallel']
        #     if steer_cmd < -self.robot_params['max_steer_angle_parallel']:
        #         steer_cmd = -self.robot_params['max_steer_angle_parallel']
        #     vel = 1.0 if msg.linear.x >= 0 else -1.0
        #     self.set_motion_command(vel * math.sqrt(msg.linear.x ** 2 + msg.linear.y ** 2), steer_cmd)
        # elif self.motion_mode == 'MOTION_MODE_SPINNING':
        #     a_v = msg.angular.z
        #     if a_v > self.robot_params['max_angular_speed']:
        #         a_v = self.robot_params['max_angular_speed']
        #     if a_v < -self.robot_params['max_angular_speed']:
        #         a_v = -self.robot_params['max_angular_speed']
        #     self.set_motion_command(0.0, 0.0, a_v)
        # elif self.motion_mode == 'MOTION_MODE_SIDE_SLIP':
        #     l_v = msg.linear.y
        #     if l_v > self.robot_params['max_linear_speed']:
        #         l_v = self.robot_params['max_linear_speed']
        #     if l_v < -self.robot_params['max_linear_speed']:
        #         l_v = -self.robot_params['max_linear_speed']
        #     self.robot.set_motion_command(0.0, 0.0, l_v)
        # if(abs(msg.linear.x)>abs(msg.angular.z) and abs(msg.angular.z) == 0):   # in-phase # A button of Xbox 360 controller 
        #     mode_selection = 2
        #     self.motion_mode = 'MOTION_MODE_PARALLEL'
        # elif(abs(msg.angular.z)>abs(msg.linear.x) and abs(msg.linear.x) != 0): # opposite phase # LB button of Xbox 360 controller 
        #     mode_selection = 1
        #     self.motion_mode = 'MOTION_MODE_DUAL_ACKERMAN'
        # elif(abs(msg.angular.z)>abs(msg.linear.x) and abs(msg.linear.x) == 0): # pivot turn # RB button of Xbox 360 controller 
        #     mode_selection = 3
        #     self.motion_mode = 'MOTION_MODE_SPINNING'
        # else:
        #     mode_selection = 4
        # # print mode, vel
        mult = 1.0
        ang_mult = 1.0
        msg_vel.linear.x = mult*msg.linear.x
        msg_vel.linear.y = mult*msg.linear.y
        msg_vel.angular.z = ang_mult*msg.angular.z

        # print mode and lin/ang vel in one line
        self.get_logger().info('mode: "%s" lin_velx: "%s" lin_vely: "%s" ang_vel: "%s"' % (self.motion_mode, msg.linear.x, msg.linear.y, msg.angular.z))
        

if __name__ == '__main__':
    rclpy.init(args=None)
    
    commander = Commander()
    # joy_subscriber = Joy_subscriber()
    teleop_sub = Teleop_sub()

    executor = rclpy.executors.MultiThreadedExecutor()
    executor.add_node(commander)
    # executor.add_node(joy_subscriber)
    executor.add_node(teleop_sub)

    executor_thread = threading.Thread(target=executor.spin, daemon=True)
    executor_thread.start()
    rate = commander.create_rate(2)
    try:
        while rclpy.ok():
            rate.sleep()
    except KeyboardInterrupt:
        pass
    
    rclpy.shutdown()
    executor_thread.join()

 