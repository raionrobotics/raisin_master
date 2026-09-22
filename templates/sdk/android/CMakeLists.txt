cmake_minimum_required(VERSION 3.14)
project(raisin_android_sdk VERSION 0.0.0 LANGUAGES C CXX)

if(NOT ANDROID)
    message(FATAL_ERROR "The Android SDK must be built with the Android NDK toolchain.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_DEBUG_POSTFIX "_debug_build" CACHE STRING "Debug library postfix")
set(RAISIN_BUILD_TEST OFF CACHE BOOL "Build unit tests" FORCE)

include("@SCRIPT_DIR@/cmake/raisin_helper.cmake")
list(PREPEND CMAKE_PREFIX_PATH "@SDK_PREFIX@")
list(APPEND CMAKE_FIND_ROOT_PATH "@SDK_PREFIX@")
set(RAISIN_MASTER_INCLUDE "@GENERATED_INCLUDE@")

# The SDK command supplies the ABI-specific CPU baseline.
if(NOT RAISIN_MARCH)
    message(FATAL_ERROR "RAISIN_MARCH must be provided by the SDK target configuration.")
endif()
include(CheckCCompilerFlag)
check_c_compiler_flag("-march=${RAISIN_MARCH}" RAISIN_MARCH_SUPPORTED)
if(NOT RAISIN_MARCH_SUPPORTED)
    message(FATAL_ERROR "RAISIN_MARCH='${RAISIN_MARCH}' is not supported by this compiler.")
endif()
add_compile_options("-march=${RAISIN_MARCH}" -Werror=return-type
        -Wno-unused-function -Wno-sign-compare
        $<$<COMPILE_LANGUAGE:CXX>:-Wno-reorder>)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    set(ENV{CCACHE_CPP2} "true")
endif()

install(DIRECTORY "@GENERATED_INCLUDE@/"
        DESTINATION include FILES_MATCHING PATTERN "*.hpp")

@TARGET_SETTINGS@

@SUB_PROJECT@
