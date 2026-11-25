import os
from dotenv import load_dotenv
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

    load_dotenv()

    return LaunchDescription([
        # Node(
        #     package='rviz2',
        #     executable='rviz2',
        #     name='rviz2',
        #     output='screen',
        # ),
        Node(
            package='mm_dev',
            executable='detector.py',
            name='obj_det',
            output='screen',
            parameters=[{'use_sim_time': False, 'depth_units':1000}],
        ),
    ])
