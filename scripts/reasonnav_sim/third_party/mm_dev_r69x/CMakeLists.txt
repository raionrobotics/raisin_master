cmake_minimum_required(VERSION 3.8)
project(mm_dev)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(ament_cmake_python REQUIRED)

find_package(rclpy REQUIRED)
find_package(std_msgs REQUIRED)
find_package(sensor_msgs REQUIRED)

if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  # the following line skips the linter which checks for copyrights
  # comment the line when a copyright and license is added to all source files
  set(ament_cmake_copyright_FOUND TRUE)
  # the following line skips cpplint (only works in a git repo)
  # comment the line when this package is in a git repo and when
  # a copyright and license is added to all source files
  set(ament_cmake_cpplint_FOUND TRUE)
  ament_lint_auto_find_test_dependencies()
endif()

# Install launch files
install(DIRECTORY
  launch
  DESTINATION share/${PROJECT_NAME}/
)

# Install config files
install(DIRECTORY
  config
  DESTINATION share/${PROJECT_NAME}/
)

# Install Python modules
ament_python_install_package(${PROJECT_NAME})

# Install Python executables
install(PROGRAMS
  nodes/teleop.py
  nodes/pan_tilt_voice.py
  nodes/frontier_explorer.py
  nodes/cloud_slice.py
  nodes/voxel_costmap.py
  nodes/sim_swerve_controller.py
  nodes/vlm_nav.py
  nodes/tf_static_filter.py
  DESTINATION lib/${PROJECT_NAME}
)

install(PROGRAMS
  mm_dev/obj_det/detection.py
  nodes/detector.py
  DESTINATION lib/${PROJECT_NAME}
)

install(PROGRAMS
  nodes/hri.py
  DESTINATION lib/${PROJECT_NAME}
)

ament_package()
