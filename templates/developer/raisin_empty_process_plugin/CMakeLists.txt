cmake_minimum_required(VERSION 3.15)
project(raisin_empty_process_plugin)

raisin_find_package(raisin_plugin REQUIRED)

add_library(${PROJECT_NAME}
        SHARED
        src/empty_process_plugin.cpp
)

target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${RAISIN_MASTER_INCLUDE}> ## headers for the message files
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME} raisin_plugin)

install(
        TARGETS ${PROJECT_NAME}
        EXPORT export_${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
)

install(
        DIRECTORY include/
        DESTINATION include
)

add_executable(${PROJECT_NAME}_process src/empty_process.cpp)
target_include_directories(${PROJECT_NAME}_process
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${RAISIN_MASTER_INCLUDE}> ## headers for the message files
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME}_process PRIVATE raisin_network)
install(
        TARGETS ${PROJECT_NAME}_process
        RUNTIME DESTINATION bin
)

add_executable(${PROJECT_NAME}_process_listener src/empty_process_listener.cpp)
target_link_libraries(${PROJECT_NAME}_process_listener PRIVATE raisin_network)
install(
        TARGETS ${PROJECT_NAME}_process_listener
        RUNTIME DESTINATION bin
)

