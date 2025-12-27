cmake_minimum_required(VERSION 3.15)
project(raisin_empty_controller)

raisin_find_package(raisin_controller REQUIRED)
raisin_find_package(raisin_data_logger REQUIRED)
add_library(${PROJECT_NAME} SHARED
        src/${PROJECT_NAME}/raibo_empty_controller.cpp
        )

target_link_libraries(${PROJECT_NAME} raisin_controller raisin_data_logger raisin_util)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${RAISIN_MASTER_INCLUDE}>
        $<INSTALL_INTERFACE:include>)

install(
        TARGETS ${PROJECT_NAME}
        EXPORT export_${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
)


