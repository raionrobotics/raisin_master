function(raisin_find_package package_name)
    if(NOT TARGET ${package_name})
        find_package(${package_name} ${ARGN})
    endif()
endfunction()

function(raisin_install_without_config PROJECT_NAME)
    # Parse optional arguments, specifically NAMESPACE
    cmake_parse_arguments(ARG "" "NAMESPACE" "" ${ARGN})

    install(DIRECTORY include/ DESTINATION include)

    # This command installs the targets and associates them with an export set.
    # It does NOT take a NAMESPACE argument itself.
    install(
            TARGETS ${PROJECT_NAME}
            EXPORT export_${PROJECT_NAME}
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
            RUNTIME DESTINATION bin
            INCLUDES DESTINATION include
            # The ${namespace_args} variable has been REMOVED from here.
    )

    # Set up namespace arguments ONLY for the install(EXPORT) command
    set(export_namespace_args)
    if(ARG_NAMESPACE)
        # The 'install(EXPORT)' command adds the '::' itself.
        set(export_namespace_args NAMESPACE ${ARG_NAMESPACE})
    endif()

    # This command installs the export file (Targets.cmake)
    # and *this* is where the namespace is applied.
    install(
            EXPORT export_${PROJECT_NAME}
            FILE ${PROJECT_NAME}Targets.cmake
            DESTINATION lib/cmake/${PROJECT_NAME}
            ${export_namespace_args} # Apply namespace ONLY here
    )
endfunction()

function(raisin_install PROJECT_NAME)
    # Parse for NAMESPACE keyword. Other args will be in ARG_UNPARSED_ARGUMENTS
    cmake_parse_arguments(ARG "" "NAMESPACE" "" ${ARGN})

    # Prepare namespace arguments to pass to the helper function
    set(namespace_args)
    if(ARG_NAMESPACE)
        set(namespace_args NAMESPACE ${ARG_NAMESPACE})
    endif()

    # Call the base installer, passing along the namespace if it exists
    raisin_install_without_config(${PROJECT_NAME} ${namespace_args})

    include(CMakePackageConfigHelpers)

    set(find_package_string "")
    # Loop over the *remaining* arguments, which are the dependencies
    foreach(libName IN LISTS ARG_UNPARSED_ARGUMENTS)
        string(APPEND find_package_string "if(NOT TARGET ${libName})\n    find_package(${libName} REQUIRED)\nendif()\n")
    endforeach()

    set(_package_config_in_content
            "@PACKAGE_INIT@\n\n${find_package_string}\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/${PROJECT_NAME}Targets.cmake\")\n"
    )

    set(_package_config_in_path "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake.in")
    file(WRITE "${_package_config_in_path}" "${_package_config_in_content}")

    configure_package_config_file(
            "${_package_config_in_path}"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
            INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
    )

    install(
            FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
            DESTINATION lib/cmake/${PROJECT_NAME}
    )
endfunction()

function(raisin_install_config_string PROJECT_NAME CONFIG_STRING)
    # Parse for NAMESPACE keyword from any extra arguments
    cmake_parse_arguments(ARG "" "NAMESPACE" "" ${ARGN})

    # Prepare namespace arguments to pass to the helper function
    set(namespace_args)
    if(ARG_NAMESPACE)
        set(namespace_args NAMESPACE ${ARG_NAMESPACE})
    endif()

    # Call the base installer, passing along the namespace if it exists
    raisin_install_without_config(${PROJECT_NAME} ${namespace_args})

    include(CMakePackageConfigHelpers)

    set(_package_config_in_content
            "@PACKAGE_INIT@\n\n${CONFIG_STRING}\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/${PROJECT_NAME}Targets.cmake\")\n"
    )

    set(_package_config_in_path "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake.in")
    file(WRITE "${_package_config_in_path}" "${_package_config_in_content}")

    configure_package_config_file(
            "${_package_config_in_path}"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
            INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
    )

    install(
            FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
            DESTINATION lib/cmake/${PROJECT_NAME}
    )
endfunction()

function(raisin_recommended_clang_tidy)
    find_program(CLANG_TIDY_EXE
            NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15 clang-tidy-14)

    if(CLANG_TIDY_EXE OR WIN32)
        return()
    endif()

    set(_clang_checks
            "-checks=clang-analyzer-*"
            ",-clang-analyzer-optin.cplusplus.UninitializedObject"
            ",-clang-analyzer-cplusplus.StringChecker"
            ",bugprone-use-after-move"
            ",bugprone-dangling-handle"
            ",bugprone-infinite-loop"
            ",bugprone-sizeof-expression"
            ",bugprone-misplaced-widening-cast"
            ",misc-dangling-handle"
            ",bugprone-return-stack-address"
            ",cppcoreguidelines-dangling-handle"
            ",cppcoreguidelines-no-dangling-reference"
            ",security.insecureAPI.*"
    )
    string(JOIN "" CLANG_TIDY_CHECKS ${_clang_checks})

    # Get full GCC version string (e.g. "11.4.0")
    execute_process(
            COMMAND ${CMAKE_CXX_COMPILER} -dumpfullversion
            OUTPUT_VARIABLE GCC_FULL_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT GCC_FULL_VERSION)
        # fallback if -dumpfullversion unsupported
        execute_process(
                COMMAND ${CMAKE_CXX_COMPILER} -dumpversion
                OUTPUT_VARIABLE GCC_FULL_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()

    # Extract major version (digits before first dot)
    string(REGEX MATCH "^[0-9]+" GCC_MAJOR_VERSION "${GCC_FULL_VERSION}")

    set(CLANG_TIDY_OPTS
            "${CLANG_TIDY_CHECKS}"
            "-warnings-as-errors=*"
            "-extra-arg=-Wno-unused-command-line-argument"
            "-extra-arg=-Qunused-arguments"
            "--extra-arg-before=-I/usr/include/c++/${GCC_MAJOR_VERSION}"
            "--extra-arg-before=-I/usr/include/x86_64-linux-gnu/c++/${GCC_MAJOR_VERSION}"
    )

    set(CMAKE_CXX_CLANG_TIDY
            "${CLANG_TIDY_EXE};${CLANG_TIDY_OPTS}"
            PARENT_SCOPE)
endfunction()

function(raisin_windows_export)
    if (WIN32)
        set_target_properties(${PROJECT_NAME} PROPERTIES
                VS_DOTNET_DOCUMENTATION_FILE_PLATFORM_UPGRADE_NEEDED TRUE
                WINDOWS_EXPORT_ALL_SYMBOLS TRUE
        )
        target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
    endif ()
endfunction()

function(raisin_enable_coverage)
    # Add gcov line coverage when building tests
    if(RAISIN_BUILD_TEST AND NOT WIN32)
        foreach(target_name IN LISTS ARGV)
            get_target_property(_target_type ${target_name} TYPE)
            if(_target_type STREQUAL "INTERFACE_LIBRARY")
                target_compile_options(${target_name} INTERFACE --coverage -O0 -g)
                target_link_libraries(${target_name} INTERFACE --coverage)
            elseif(_target_type STREQUAL "STATIC_LIBRARY")
                target_compile_options(${target_name} PRIVATE --coverage -O0 -g)
                target_link_libraries(${target_name} INTERFACE --coverage)
            else()
                target_compile_options(${target_name} PRIVATE --coverage -O0 -g)
                target_link_options(${target_name} PRIVATE --coverage)
            endif()
        endforeach()
    endif()
endfunction()

macro(raisin_linux_only)
    if(WIN32)
        # This will return from the scope that *calls* the macro
        return()
    endif()
endmacro()

macro(raisin_windows_only)
    if(NOT WIN32)
        # This will return from the scope that *calls* the macro
        return()
    endif()
endmacro()

#=============================================================================
# FUNCTION: update_build_dir_in_yaml
#
# Description:
#   Executes an external Python script to safely update a YAML file with the
#   build directory path. This approach is robust and preserves YAML structure.
#
# Arguments:
#   CONFIG_FILE_PATH - The absolute path to the YAML configuration file.
#
#=============================================================================
function(update_build_dir_in_yaml CONFIG_FILE_PATH)
    # Find a Python interpreter on the system
    find_package(PythonInterp REQUIRED)

    # Path to our helper script
    set(YAML_UPDATE_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/update_build_directories.py")

    if(NOT EXISTS ${YAML_UPDATE_SCRIPT})
        message(FATAL_ERROR "YAML update script not found at ${YAML_UPDATE_SCRIPT}")
        return()
    endif()

    # Determine the key based on the build type
    set(yaml_key "")
    if(CMAKE_BUILD_TYPE MATCHES "^Debug$")
        set(yaml_key "debug_build_dir")
    elseif(CMAKE_BUILD_TYPE MATCHES "^Release$")
        set(yaml_key "release_build_dir")
    else()
        message(STATUS "Build type is '${CMAKE_BUILD_TYPE}'. No configuration setting will be updated.")
        return()
    endif()

    # Get the native path for the current build directory
    file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}" yaml_value)

    # Execute the Python script to perform the update
    message(STATUS "Running YAML update script for ${CONFIG_FILE_PATH}...")
    execute_process(
            COMMAND ${PYTHON_EXECUTABLE} ${YAML_UPDATE_SCRIPT} "${CONFIG_FILE_PATH}" "${yaml_key}" "${yaml_value}"
            RESULT_VARIABLE process_result
            OUTPUT_VARIABLE process_output
            ERROR_VARIABLE process_error
    )

    # Check if the script executed successfully
    if(NOT process_result EQUAL 0)
        message(FATAL_ERROR "Python script failed to update YAML file.\n"
                "Result: ${process_result}\n"
                "Output: ${process_output}\n"
                "Error: ${process_error}")
    else()
        # Print the script's success message
        message(STATUS "${process_output}")
    endif()

endfunction()