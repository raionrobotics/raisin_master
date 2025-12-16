cmake_minimum_required(VERSION 3.14)
project("raisin_master" VERSION 0.0.0)
set(CMAKE_CXX_STANDARD 17)       # Use C++17
set(CMAKE_CXX_STANDARD_REQUIRED ON) # Ensure the standard is required
set(CMAKE_CXX_EXTENSIONS OFF)       # Disable compiler-specific extensions (e.g., GNU extensions)

# Block vcpkg on Linux
if(UNIX AND NOT APPLE)
    if(DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
        message(FATAL_ERROR "vcpkg is not supported on Linux. Please build without the vcpkg toolchain.")
    endif()
endif()

option(RAISIN_RELEASE_BUILD "Build unit tests for the project" OFF)

@@RAISIN_BUILD_TEST_OVERRIDE@@
option(RAISIN_BUILD_TEST "Build unit tests for the project" ON)

if(NOT RAISIN_RELEASE_BUILD)
    set(CMAKE_INSTALL_PREFIX "@@SCRIPT_DIR@@/install")
endif()

include(@@SCRIPT_DIR@@/cmake/raisin_helper.cmake)

# Build CMAKE_PREFIX_PATH with install dir and the current build's install prefix
list(APPEND CMAKE_PREFIX_PATH "@@SCRIPT_DIR@@/install" "${CMAKE_INSTALL_PREFIX}")
list(REMOVE_DUPLICATES CMAKE_PREFIX_PATH)
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH}" CACHE PATH "Search paths for CMake packages" FORCE)
set(RAISIN_MASTER_INCLUDE @@SCRIPT_DIR@@/generated/include CACHE STRING "include path")
set(CMAKE_DEBUG_POSTFIX "_debug_build" CACHE STRING "Debug Postfix for lib, samples and tools")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
    add_compile_options(-Werror=return-type)
    add_compile_options(-Wno-unused-function)
    add_compile_options(-Wno-sign-compare)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wno-reorder>)
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4267") # mute possible loss of data (precision mismatch)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()

## Top-level CMakeLists.txt
#set(SAN_FLAGS "-fsanitize=address,undefined,leak -fno-omit-frame-pointer")
#
#foreach(lang C CXX)
#    set(CMAKE_${lang}_FLAGS_DEBUG
#            "${CMAKE_${lang}_FLAGS_DEBUG} ${SAN_FLAGS}")
#endforeach()
#
#set(CMAKE_EXE_LINKER_FLAGS_DEBUG
#        "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined,leak")
#set(CMAKE_SHARED_LINKER_FLAGS_DEBUG
#        "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined,leak")

if((CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU"))
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        message(STATUS "Using ccache to speed up incremental builds")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
        set(ENV{CCACHE_CPP2} "true")
    endif()
endif()

update_build_dir_in_yaml(${CMAKE_CURRENT_SOURCE_DIR}/configuration_setting.yaml)

install(DIRECTORY generated/include/
        DESTINATION include  # where to install the headers
        FILES_MATCHING PATTERN "*.hpp"     # only install .hpp files
)

@@SUB_PROJECT@@


if (WIN32)
    install(DIRECTORY "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/"
            DESTINATION "."
    )
    add_compile_options("/utf-8")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(/wd4251 /wd4275)
endif()
