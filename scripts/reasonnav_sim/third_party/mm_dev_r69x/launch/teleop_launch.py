import os
from ament_index_python.packages import get_package_share_directory

from launch import LaunchDescription
from launch.actions import IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch_xml.launch_description_sources import XMLLaunchDescriptionSource
from launch_ros.actions import Node

def generate_launch_description():
    config = os.path.join(
        get_package_share_directory('mm_dev'),
        'config',
        'mm_dev_params.yaml',
    )

    moveit_servo_launch_file = os.path.join(
        get_package_share_directory('mm_dev'),
        "launch", "moveit_servo_realmove.launch.py"
    )
    moveit_servo = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            moveit_servo_launch_file
        ),
        launch_arguments={
            'dof': '7',
            'add_gripper':'true',
            'robot_ip':'192.168.1.236',
            'joystick_type': '-1',
            'ros2_control_plugin': 'uf_robot_hardware/UFRobotSystemHardware'
        }.items()
    )
    ranger_launch_file = os.path.join(
        get_package_share_directory('ranger_bringup'),
        "launch", "ranger_mini_v2.launch.xml"
    )
    ranger_bringup = IncludeLaunchDescription(
        XMLLaunchDescriptionSource(ranger_launch_file),
        launch_arguments={
            'publish_odom_tf':'true'
        }.items()
    )

    lidar_launch_file = os.path.join(
        get_package_share_directory('sllidar_ros2'),
        "launch", "sllidar_a1_launch.py"
    )
    lidar_node = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            lidar_launch_file
        ),
        launch_arguments={
            'frame_id': 'rplidar_a1_v3_1'
        }.items()
    )
    static_tf = Node(
        package="tf2_ros",
        executable="static_transform_publisher",
        output="screen" ,
        arguments=["0.296", "-0.181", "-0.001", "0", "0", "0", "base_link", "rplidar_a1_v3_1"]
    )
    return LaunchDescription([
        moveit_servo,
        # static_tf,
        # lidar_node,
        ranger_bringup,
        Node(
            package='joy',
            executable='joy_node',
            name='joy_node',
            output='screen'
        ),
        Node(
            package='mm_dev',
            executable='teleop.py',
            name='teleop',
            output='screen',
            parameters=[config],
        ),
    ])
