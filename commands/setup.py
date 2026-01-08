"""
Setup command for RAISIN.

Generates message/service headers and configures CMakeLists.txt.
"""

import os
import re
import sys
import glob
import yaml
import shutil
import platform
import subprocess
import requests
import click
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Dict, Any, Set, Optional

from commands.repo_dependency_check import guard_src_repo_release_yaml_dependencies

# Import globals, constants, and utilities
from commands import globals as g
from commands.constants import Colors, TYPE_MAPPING, STRING_TYPES
from commands.utils import (
    load_configuration,
    delete_directory,
    get_repo_name_from_path,
)


# ============================================================================
# Click CLI Command
# ============================================================================


@click.command()
@click.option(
    "--no_test",
    is_flag=True,
    help="Disable building unit tests for this setup run",
)
@click.argument("targets", nargs=-1)
def setup_command(no_test, targets):
    """
    Generate interface files (.msg, .srv, .action) and configure CMake.

    \b
    Examples:
        raisin setup                        # Build all packages
        raisin setup raisin_network         # Build specific package
        raisin setup raibo_controller gui   # Build multiple packages
    """
    targets = list(targets)
    process_build_targets(targets)

    if not g.build_pattern:
        click.echo("🛠️  building all patterns")
    else:
        click.echo(f"🛠️  building the following targets: {g.build_pattern}")

    setup(build_test_enabled=(not no_test))


def process_build_targets(targets):
    """
    Process build targets and update global build_pattern.

    Args:
        targets: List of target names or paths

    This function parses RAISIN_BUILD_TARGETS.yaml files and updates g.build_pattern
    based on the requested targets.
    """
    script_directory = g.script_directory
    repos_to_ignore = set(get_repos_to_ignore())

    # Check if targets specify a directory path
    if len(targets) > 1 and (Path(script_directory) / "src" / targets[0]).exists():
        repo_name = get_repo_name_from_path(Path(script_directory) / "src" / targets[0])
        if repo_name and repo_name in repos_to_ignore:
            click.echo(
                f"⚠️  Repository '{repo_name}' is configured to be ignored. Skipping."
            )
            g.build_pattern = []
            return

        g.build_pattern = [
            name
            for name in os.listdir(Path(script_directory) / "src" / targets[0])
            if os.path.isdir(
                os.path.join(Path(script_directory) / "src" / targets[0], name)
            )
        ]
    else:
        all_build_maps = {}
        yaml_search_path = os.path.join(
            script_directory, "src", "**", "RAISIN_BUILD_TARGETS.yaml"
        )

        for filepath in glob.glob(yaml_search_path, recursive=True):
            repo_name = get_repo_name_from_path(filepath)
            if repo_name and repo_name in repos_to_ignore:
                continue

            with open(filepath, "r") as f:
                try:
                    yaml_content = yaml.safe_load(f)
                    if yaml_content:
                        all_build_maps.update(yaml_content)
                except yaml.YAMLError as e:
                    click.echo(
                        f"Warning: Could not parse YAML file {filepath}. Error: {e}",
                        err=True,
                    )

        # Collect build patterns based on the input targets
        found_patterns = []
        for target in targets:
            patterns_for_target = all_build_maps.get(target, [])
            found_patterns.extend(patterns_for_target)

        g.build_pattern = found_patterns


def create_service_file(srv_file, project_directory, install_dir):
    """
    Create a service file based on the template, replacing the appropriate placeholders.
    The file is saved in <g.script_directory>/include/<project_directory>/srv.

    :param srv_file: Path to the .srv file
    :param project_directory: Path to the project directory
    :param install_dir: Installation directory
    """
    template_path = os.path.join(g.script_directory, "templates", "ServiceTemplate.hpp")

    # Extract the project name from the project directory path
    project_name = os.path.basename(project_directory)

    # Determine the target directory in include/<project_name>/srv
    include_project_srv_dir = os.path.join(
        g.script_directory, "generated", "include", project_name, "srv"
    )

    # Recreate the directory to ensure it's clean
    os.makedirs(include_project_srv_dir, exist_ok=True)

    destination_file = os.path.join(install_dir, "messages", project_name, "srv", "")
    os.makedirs(destination_file, exist_ok=True)
    shutil.copy2(srv_file, destination_file)

    # Read the template
    with open(template_path, "r") as template_file:
        template_content = template_file.read()

    # Extract service name from the file
    service_name = os.path.basename(srv_file).replace(".srv", "")

    # Read the service file and split it into request and response parts
    with open(srv_file, "r") as srv_file_content:
        srv_content = srv_file_content.read()

    with open(srv_file, "r") as srv_file_content:
        lines = srv_file_content.readlines()

    # Split the content into request and response sections
    if "---" in srv_content:
        request_content, response_content = srv_content.split("---", 1)
    else:
        # If no '---' line is found, it's not a valid service file.
        print(f"Invalid service file format: {srv_file}")
        return

    includes = []

    for line in lines:
        line = line.strip()

        # Ignore comments by splitting at '#' and taking the part before it
        line = line.split("#", 1)[0].strip()

        # Skip empty lines
        if not line or line[0] == "-":
            continue

        parts = line.split()
        if len(parts) == 2:
            data_type, data_name = parts

            # Transform the data type for arrays
            transformed_type, base_type, subproject_path, found_type = (
                transform_data_type(data_type, project_name)
            )

            # Check if the type is a known message type (not a primitive)
            if not found_type and transformed_type != "Header":
                # Use the preferred include format with relative path
                if not subproject_path:
                    subproject_path = project_name

                snake_str = re.sub(
                    r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))",
                    "_",
                    base_type,
                ).lower()
                snake_str = snake_str.replace("__", "_")
                includes.append(
                    f'#include "../../{subproject_path}/msg/{snake_str}.hpp"'
                )

    # Process the request and response contents
    request_includes, request_members, request_buffer_members, request_buffer_size = (
        process_service_content(request_content, project_name)
    )
    (
        response_includes,
        response_members,
        response_buffer_members,
        response_buffer_size,
    ) = process_service_content(response_content, project_name)

    # Replace placeholders in the template
    class_name = service_name.replace("_", "")
    service_content = template_content.replace("@@SERVICE_NAME@@", class_name)
    service_content = service_content.replace("@@INCLUDE_PATH@@", "\n".join(includes))
    service_content = service_content.replace(
        "@@REQUEST_INCLUDES@@", "\n".join(request_includes)
    )
    service_content = service_content.replace(
        "@@REQUEST_MEMBERS@@", "\n  ".join(request_members)
    )

    request_set_buffer_member_string = ""
    request_get_buffer_member_string = ""
    request_equal_buffer_member_string = ""
    response_set_buffer_member_string = ""
    response_get_buffer_member_string = ""
    response_equal_buffer_member_string = ""

    for bm in request_buffer_members:
        request_set_buffer_member_string += f"::raisin::setBuffer(buffer, {bm});\n"
        request_get_buffer_member_string += f"temp = ::raisin::getBuffer(temp, {bm});\n"
        request_equal_buffer_member_string += f"&& this->{bm} == other.{bm} \n"

    for bm in response_buffer_members:
        response_set_buffer_member_string += f"::raisin::setBuffer(buffer, {bm});\n"
        response_get_buffer_member_string += (
            f"temp = ::raisin::getBuffer(temp, {bm});\n"
        )
        response_equal_buffer_member_string += f"&& this->{bm} == other.{bm} \n"

    service_content = service_content.replace(
        "@@REQUEST_SET_BUFFER_MEMBERS@@", request_set_buffer_member_string
    )
    modified_request_set_buffer_member_string = "\n".join(
        "buffer = " + line for line in request_set_buffer_member_string.splitlines()
    )
    service_content = service_content.replace(
        "@@REQUEST_SET_BUFFER_MEMBERS2@@", modified_request_set_buffer_member_string
    )
    service_content = service_content.replace(
        "@@REQUEST_GET_BUFFER_MEMBERS@@", request_get_buffer_member_string
    )
    service_content = service_content.replace(
        "@@REQUEST_EQUAL_BUFFER_MEMBERS@@", request_equal_buffer_member_string
    )
    service_content = service_content.replace(
        "@@REQUEST_BUFFER_SIZE@@", "\n  ".join(request_buffer_size)
    )

    service_content = service_content.replace(
        "@@RESPONSE_SET_BUFFER_MEMBERS@@", response_set_buffer_member_string
    )
    modified_response_set_buffer_member_string = "\n".join(
        "buffer = " + line for line in response_set_buffer_member_string.splitlines()
    )
    service_content = service_content.replace(
        "@@RESPONSE_SET_BUFFER_MEMBERS2@@", modified_response_set_buffer_member_string
    )
    service_content = service_content.replace(
        "@@RESPONSE_GET_BUFFER_MEMBERS@@", response_get_buffer_member_string
    )
    service_content = service_content.replace(
        "@@RESPONSE_EQUAL_BUFFER_MEMBERS@@", response_equal_buffer_member_string
    )
    service_content = service_content.replace(
        "@@RESPONSE_BUFFER_SIZE@@", "\n  ".join(response_buffer_size)
    )

    service_content = service_content.replace(
        "@@RESPONSE_INCLUDES@@", "\n".join(response_includes)
    )
    service_content = service_content.replace(
        "@@RESPONSE_MEMBERS@@", "\n  ".join(response_members)
    )

    buffer_member_string = ", ".join(response_buffer_members)
    buffer_member_string = (
        f", {buffer_member_string}" if response_buffer_members else buffer_member_string
    )
    service_content = service_content.replace(
        "@@RESPONSE_BUFFER_MEMBERS@@", buffer_member_string
    )
    service_content = service_content.replace("@@PROJECT_NAME@@", project_name)

    # Create the service file in the <g.script_directory>/include/<project_directory>/srv directory
    snake_str = re.sub(
        r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))", "_", service_name
    ).lower()
    snake_str = snake_str.replace("__", "_")
    output_path = os.path.join(include_project_srv_dir, f"{snake_str}.hpp")

    with open(output_path, "w") as output_file:
        output_file.write(service_content)


def build_string_size_expr(string_type, value_expr):
    if string_type == "std::u16string":
        return f"{value_expr}.size() * sizeof(char16_t)"
    return f"{value_expr}.size()"


def build_sequence_size_entry(is_vector, base_type, data_name, line_suffix):
    if base_type in STRING_TYPES:
        string_size_expr = build_string_size_expr(base_type, "v")
        loop = (
            f"for (const auto& v : {data_name}) temp += sizeof(uint32_t) + {string_size_expr};"
        )
        if is_vector:
            return f"temp += sizeof(uint32_t); \n {loop}{line_suffix}"
        return f"{loop}{line_suffix}"

    if base_type in TYPE_MAPPING.values():
        size_expr = f"{data_name}.size() * sizeof({base_type})"
        if is_vector:
            return f"temp += sizeof(uint32_t) + {size_expr};{line_suffix}"
        return f"temp += {size_expr};{line_suffix}"

    if is_vector:
        loop = f"for (const auto& v : {data_name}) temp += v.getSize();"
        return f"temp += sizeof(uint32_t); \n {loop}{line_suffix}"

    return f"for (const auto& v : {data_name}) temp += v.getSize();{line_suffix}"


def process_service_content(content, project_name):
    """
    Process the service content (either request or response part).
    It returns the includes, members, and buffer_members lists.
    """
    includes = []
    members = []
    buffer_members = []
    buffer_size = []

    for line in content.splitlines():
        line = line.strip()

        # Ignore comments
        line = line.split("#", 1)[0].strip()

        # Skip empty lines
        if not line:
            continue

        parts = line.split()
        parts_in_two = line.split(" ", 1)

        if len(parts) < 4 and "=" not in parts_in_two[1]:
            initial_value = ""
            if len(parts) == 3:
                data_type, data_name, initial_value = parts
            else:
                data_type, data_name = parts

            # Transform the data type for arrays
            transformed_type, base_type, subproject_path, found_type = (
                transform_data_type(data_type, project_name)
            )
            data_name = re.sub(
                r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))",
                "_",
                data_name,
            ).lower()
            data_name = data_name.replace("__", "_")

            # Check if the type is a known message type (not a primitive)
            if not found_type and transformed_type != "Header":
                # Use the preferred include format with relative path
                includes.append(
                    f'#include "../../{subproject_path}/msg/{base_type}.hpp"'
                )

            members.append(f"using _{data_name}_type = {transformed_type};")
            if len(parts) == 3:
                members.append(f"{transformed_type} {data_name} = {initial_value};")
            else:
                members.append(f"{transformed_type} {data_name};")

            buffer_members.append(f"{data_name}")

            is_vector = transformed_type.startswith("std::vector")
            if is_vector or transformed_type.startswith("std::array"):
                buffer_size.append(
                    build_sequence_size_entry(is_vector, base_type, data_name, "\n")
                )
            else:
                if transformed_type in STRING_TYPES:
                    string_size_expr = build_string_size_expr(
                        transformed_type, data_name
                    )
                    buffer_size.append(
                        f"temp += sizeof(uint32_t) + {string_size_expr};\n"
                    )
                elif (
                    transformed_type in TYPE_MAPPING.values()
                    and transformed_type != "std::string"
                    and transformed_type != "std::u16string"
                ):
                    buffer_size.append(f"temp += sizeof({data_name});\n")
                else:
                    buffer_size.append(f"temp += {data_name}.getSize();\n")

        elif "=" in line:
            parts = line.split(" ", 1)
            members.append(f"static constexpr {TYPE_MAPPING[parts[0]]} {parts[1]};")

    return includes, members, buffer_members, buffer_size


def find_topic_directories(search_directories):
    """
    Search for all subdirectories in <g.script_directory> containing 'CMakeLists.txt'.
    Return a list of these directories.
    The function will not search further into subdirectories once a 'CMakeLists.txt' file is found.
    :param search_directories: A list of directories to search (e.g., ['src', 'messages']).
    """

    topic_directories = []

    # Walk through the specified directories
    for search_dir in search_directories:
        search_path = os.path.join(g.script_directory, search_dir)

        for root, dirs, files in os.walk(search_path):
            if "msg" in dirs or "srv" in dirs:
                # Add the directory containing CMakeLists.txt to the list
                topic_directories.append(root)
                # Do not recurse into subdirectories (clear the dirs list)
                dirs.clear()

    return topic_directories


def find_project_directories(
    search_directories, install_dir, packages_to_ignore=None, repos_to_ignore=None
):
    """
    Search for all subdirectories in <g.script_directory> containing 'CMakeLists.txt'.
    Return a list of these directories.
    The function will not search further into subdirectories once a 'CMakeLists.txt' file is found.

    :param install_dir:
    :param packages_to_ignore:
    :param search_directories: A list of directories to search (e.g., ['src', 'messages']).
    """

    if packages_to_ignore is None:
        packages_to_ignore = []
    repo_ignore_set = set(repos_to_ignore or [])
    project_directories = []

    # Walk through the specified directories
    for search_dir in search_directories:
        search_path = os.path.join(g.script_directory, search_dir)

        for root, dirs, files in os.walk(search_path):
            if repo_ignore_set:
                repo_name = get_repo_name_from_path(root)
                if repo_name and repo_name in repo_ignore_set:
                    dirs.clear()
                    continue
            project_name = os.path.basename(root)
            if project_name in packages_to_ignore:
                dirs.clear()
                continue
            if "CMakeLists.txt" in files:
                # Add the directory containing CMakeLists.txt to the list
                project_directories.append(root)
                # Do not recurse into subdirectories (clear the dirs list)
                dirs.clear()

    for project_directory in project_directories:
        # Directories to copy
        directories_to_copy = ["resource", "config", "scripts"]

        for directory in directories_to_copy:
            # Construct the target directory path
            target_directory = os.path.join(
                g.script_directory,
                install_dir,
                directory,
                os.path.basename(project_directory),
            )

            # Ensure the target directory exists, create it if not
            source_dir = os.path.join(project_directory, directory)

            # Check if the source directory exists
            if os.path.exists(source_dir):
                # Define the target path for this directory
                os.makedirs(target_directory, exist_ok=True)
                target_path = os.path.join(target_directory, directory)

                # Copy the entire directory
                shutil.copytree(source_dir, target_path, dirs_exist_ok=True)

    return project_directories


def find_interface_files(
    search_directories,
    interface_types,
    packages_to_ignore=None,
    repos_to_ignore=None,
):
    """
    Finds ROS interface files (e.g., .action, .msg, .srv) in specified directories.

    Args:
        g.script_directory (str): The base path from which to search.
        search_directories (list): A list of subdirectories to search within.
        interface_types (list): A list of interface types to find, e.g., ['action', 'msg', 'srv'].
        packages_to_ignore (list, optional): A list of package names to skip. Defaults to None.

    Returns:
        tuple: A tuple of lists, where each list contains the file paths for an interface
               type, in the same order as specified in `interface_types`.
    """
    if packages_to_ignore is None:
        packages_to_ignore = []
    repo_ignore_set = set(repos_to_ignore or [])

    # This dictionary maps an interface type (e.g., 'action') to its file extension
    # and the list where its found files will be stored.
    interface_map = {interface: (f".{interface}", []) for interface in interface_types}

    for search_dir in search_directories:
        search_path = Path(g.script_directory) / search_dir
        generated_dest_dir = Path(g.script_directory) / "generated" / "include"

        if not os.path.isdir(search_path):
            continue

        for root, dirs, files in os.walk(search_path):
            if repo_ignore_set:
                repo_name = get_repo_name_from_path(root)
                if repo_name and repo_name in repo_ignore_set:
                    dirs.clear()
                    continue
            # Prune the search if the package directory should be ignored
            if os.path.basename(root) in packages_to_ignore:
                dirs.clear()
                continue

            if (Path(root) / "include").is_dir():
                if (Path(root) / "msg").is_dir() or (Path(root) / "srv").is_dir():
                    shutil.copytree(
                        Path(root) / "include", generated_dest_dir, dirs_exist_ok=True
                    )

            # The name of the directory we are currently in (e.g., 'msg', 'srv')
            current_dir_name = os.path.basename(root)

            # Check if this directory's name matches an interface type we're looking for
            if current_dir_name in interface_map:
                extension, target_list = interface_map[current_dir_name]

                for filename in files:
                    if filename.endswith(extension):
                        full_path = os.path.join(root, filename)
                        target_list.append(full_path)

                # We found an interface directory (e.g., '.../my_package/msg'),
                # so we don't need to search its subdirectories.
                dirs.clear()

    # Extract the populated lists from the map in the correct order
    # and return them as a tuple.
    return tuple(interface_map[interface][1] for interface in interface_types)


def build_dependency_graph(project_directories):
    """
    Build a dependency graph from the list of project directories.
    Each node is a project, and edges represent dependencies (based on find_package).

    The graph is a defaultdict where:
    - key: project_name
    - value: set of dependencies (projects that project_name depends on)

    Parameters:
    - project_directories: List of directories containing the projects.

    Returns:
    - graph: A dictionary where each project has a set of dependencies.
    - in_degree: A dictionary tracking how many dependencies each project has.
    """
    graph = defaultdict(list)

    # Iterate through each project directory
    for project_dir in project_directories:
        # Path to the CMakeLists.txt file for this project
        cmake_file_path = os.path.join(project_dir, "CMakeLists.txt")

        # Find the project name (assumes the project name is the directory name or can be derived)
        project_name = os.path.basename(project_dir)

        # Get the dependencies of this project
        dependencies = find_dependencies(cmake_file_path)
        graph[project_name] = dependencies

    for key in list(graph.keys()):
        # Keep only elements in the list that are keys of the defaultdict
        graph[key] = [elem for elem in graph[key] if elem in graph]

    return graph


def find_dependencies(cmake_file_path):
    dependencies = []
    try:
        with open(cmake_file_path, "r") as cmake_file:
            # Read the entire file as a single string to handle multi-line target_link_libraries
            cmake_content = cmake_file.read()

        # Define the regex pattern to match "raisin_find_package(SOMETHING)"
        pattern = r"raisin_find_package\((.*?)\)"

        # List of keywords to ignore (in capital letters)
        ignored_keywords = {
            "REQUIRED",
            "VERSION",
            "CONFIG",
            "COMPONENTS",
            "QUIET",
            "EXACT",
        }

        # Use re.findall() to find all matches for the pattern
        matches = re.findall(pattern, cmake_content)

        # Filter out matches that are keywords in capital letters
        for match in matches:
            if match not in ignored_keywords:
                modified_match = match
                for cmake_keyword in ignored_keywords:
                    modified_match = modified_match.replace(cmake_keyword, "").strip()

                dependencies.append(modified_match)

        return dependencies

    except FileNotFoundError:
        print(f"Error: The file at {cmake_file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return dependencies


def move_key_before(dep, keys, key):
    """
    Move `key` right before `before_key` in the list of keys,
    but only if it's not already before `before_key`.
    """

    # Find the index of before_key
    dep_index = keys.index(dep)
    key_index = keys.index(key)

    # Check if the key is already before the before_key
    if key_index > dep_index:
        return keys  # Return the original list without changes

    # Remove the key from its current position
    keys.remove(key)

    # Insert the key right before the given before_key
    keys.insert(dep_index, key)

    return keys


def topological_sort(graph, keys):
    """
    Perform a topological sort on the dependency graph.
    Returns a list of keys sorted in dependency order.
    """

    # Iterate over the keys and check if they appear in the values
    original_keys = keys.copy()

    for i in range(20):
        previous_keys = keys.copy()
        for key in original_keys:
            for dep in graph[key]:  # For each key's dependencies in its value
                if dep in graph:
                    # Move the dependent `dep` before the key in the list, if not already before
                    keys = move_key_before(dep, keys, key)

        if previous_keys == keys:
            return keys

        if i == 19:
            print(f"Cyclic dependency detected")
            sys.exit(1)

    return keys


def update_cmake_file(project_directories, cmake_dir, build_test_enabled: bool):
    """
    Generate a new CMakeLists.txt file by adding projects that either match
    the global 'g.build_pattern' (if not empty) or all projects, including their
    full dependency trees.
    """
    # 1. Always build the full dependency graph first to know all relationships
    full_graph = build_dependency_graph(project_directories)
    all_project_names = list(full_graph.keys())

    projects_to_include = set()

    # 2. If g.build_pattern is set, filter projects. Otherwise, include all.
    if not g.build_pattern:
        # If g.build_pattern is empty, include all discovered projects
        projects_to_include = set(all_project_names)
    else:
        # Find initial projects matching the build patterns
        initial_matches = {
            name
            for name in all_project_names
            for pattern in g.build_pattern
            if fnmatch.fnmatch(name, pattern)
        }

        # Find all dependencies for the matched projects recursively
        queue = list(initial_matches)
        visited = set()
        while queue:
            project_name = queue.pop(0)
            if project_name in visited:
                continue

            visited.add(project_name)
            projects_to_include.add(project_name)

            # Add its dependencies to the queue to be processed
            dependencies = full_graph.get(project_name, [])
            queue.extend(dependencies)

    # 3. Create a new graph containing only the projects to be included
    filtered_graph = {
        project: [dep for dep in deps if dep in projects_to_include]
        for project, deps in full_graph.items()
        if project in projects_to_include
    }

    # 4. Perform a topological sort on the filtered set of projects
    sorted_project_names = list(filtered_graph.keys())
    for _ in range(2):  # Assuming this double-sort is for stabilization
        sorted_project_names = topological_sort(filtered_graph, sorted_project_names)

    # 5. Generate the CMakeLists.txt content from the sorted, filtered list
    template_path = os.path.join(g.script_directory, "templates", "CMakeLists.txt")
    with open(template_path, "r") as template_file:
        cmake_template_content = template_file.read()

    # Create a quick lookup from project name to its full directory path
    project_dir_map = {os.path.basename(d): d for d in project_directories}

    subdirectory_lines = []
    for project_name in sorted_project_names:
        if project_name in project_dir_map:
            project_dir = project_dir_map[project_name]
            if (Path(project_dir) / "CMakeLists.txt").is_file():
                project_dir = project_dir.replace("\\", "/")
                subdirectory_lines.append(f"add_subdirectory({project_dir})")

    cmake_content = cmake_template_content.replace(
        "@@SUB_PROJECT@@", "\n".join(subdirectory_lines)
    )
    cmake_content = cmake_content.replace("@@SCRIPT_DIR@@", g.script_directory)
    cmake_content = cmake_content.replace(
        "@@RAISIN_BUILD_TEST_OVERRIDE@@",
        ""
        if build_test_enabled
        else 'set(RAISIN_BUILD_TEST OFF CACHE BOOL "Build unit tests for the project" FORCE)',
    )

    cmake_file_path = os.path.join(g.script_directory, "CMakeLists.txt")

    with open(cmake_file_path, "w") as cmake_file:
        cmake_file.write(cmake_content)

    print(
        f"📂 Generated CMakeLists.txt at {cmake_file_path} with {len(subdirectory_lines)} projects."
    )


def transform_data_type(data_type, project_name):
    """
    Transform the data type based on whether it ends in [] or [N].
    """
    found_type = False
    subproject_path = ""

    # Split the data_type by '/' and take the last part
    if "/" in data_type:
        subproject_path, data_type = data_type.rsplit("/", 1)
        if not data_type:
            data_type = subproject_path
            subproject_path = ""

    stripped_data_type = data_type.split("<", 1)[0]
    stripped_data_type = stripped_data_type.split(">", 1)[0]

    # Check for array types (with [] or [N])
    if match := re.match(r"([a-zA-Z0-9_]+)\[(\d+)\]", data_type):
        # Fixed-size array ([N])
        base_type, size = match.groups()
        if base_type in TYPE_MAPPING:
            converted_base_type = TYPE_MAPPING[base_type]
            return (
                f"std::array<{converted_base_type}, {size}>",
                converted_base_type,
                subproject_path,
                base_type in TYPE_MAPPING,
            )
        elif not subproject_path:
            return (
                f"std::array<{project_name}::msg::{base_type}, {size}>",
                base_type,
                subproject_path,
                True,
            )
        elif subproject_path:
            return (
                f"std::array<{subproject_path}::msg::{base_type}, {size}>",
                base_type,
                subproject_path,
                False,
            )
    elif data_type.endswith("]"):
        base_type = data_type.split("[", 1)[0]  # Remove the '[]'
        if base_type in TYPE_MAPPING:
            base_type = TYPE_MAPPING[base_type]
            found_type = True
            return f"std::vector<{base_type}>", base_type, subproject_path, found_type
        elif not subproject_path:
            return (
                f"std::vector<{project_name}::msg::{base_type}>",
                base_type,
                subproject_path,
                False,
            )
        elif subproject_path:
            return (
                f"std::vector<{subproject_path}::msg::{base_type}>",
                base_type,
                subproject_path,
                False,
            )
    elif stripped_data_type in TYPE_MAPPING:
        return (
            TYPE_MAPPING[stripped_data_type],
            TYPE_MAPPING[stripped_data_type],
            subproject_path,
            True,
        )
    elif subproject_path:
        return f"{subproject_path}::msg::{data_type}", data_type, subproject_path, False
    else:
        return f"{project_name}::msg::{data_type}", data_type, subproject_path, False


def create_action_file(action_file, project_directory, install_dir):
    """
    Create a message file based on the template, replacing '@@MESSAGE_NAME@@' with the message file name.
    The file is saved in <g.script_directory>/include/<project_directory>/msg.
    """
    template_path = os.path.join(g.script_directory, "templates", "ActionTemplate.hpp")

    # Extract the project name from the project directory path
    project_name = os.path.basename(project_directory)

    # Determine the target directory in include/<project_name>/msg
    include_project_msg_dir = os.path.join(
        g.script_directory, "generated", "include", project_name, "action"
    )
    destination_file = os.path.join(install_dir, "messages", project_name, "action", "")
    os.makedirs(destination_file, exist_ok=True)
    shutil.copy2(action_file, destination_file)

    # Delete the entire include directory before generating new files
    os.makedirs(include_project_msg_dir, exist_ok=True)  # Recreate it

    # Read the template
    with open(template_path, "r") as template_file:
        template_content = template_file.read()

    # Replace the placeholder with the message file name
    message_name = str(os.path.basename(action_file).replace(".action", ""))
    class_name = message_name.replace("_", "")
    message_content = template_content.replace(
        "@@LOWER_MESSAGE_NAME@@", class_name.lower()
    )
    message_content = message_content.replace("@@MESSAGE_NAME@@", class_name)
    message_content = message_content.replace("@@PROJECT_NAME@@", project_name)

    # Create the message file in the <g.script_directory>/include/<project_directory>/msg directory
    snake_str = re.sub(
        r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))", "_", message_name
    ).lower()
    snake_str = snake_str.replace("__", "_")
    output_path = os.path.join(include_project_msg_dir, f"{snake_str}.hpp")

    with open(output_path, "w") as output_file:
        output_file.write(message_content)

    ### create other interface files
    action_path = Path(action_file)
    # --- 1. Read the action file ---
    try:
        action_file_content = action_path.read_text()
    except FileNotFoundError:
        print(f"❌ ERROR: File not found at '{action_path}'. Please check the path.")
        return
    except Exception as e:
        print(f"❌ ERROR: Could not read file: {e}")
        return

    msg_dir = Path(g.script_directory) / "temp" / project_name / "msg"
    srv_dir = Path(g.script_directory) / "temp" / project_name / "srv"
    msg_dir.mkdir(parents=True, exist_ok=True)
    srv_dir.mkdir(parents=True, exist_ok=True)

    # --- 3. Split the action file content ---
    parts = action_file_content.split("---")
    if len(parts) != 3:
        print(
            f"❌ ERROR: Invalid action file format of {action_file}. Must contain two '---' separators."
        )
        return

    goal_content, result_content, feedback_content = [part.strip() for part in parts]

    # --- 4. Write each message file ---
    message_definitions = {
        f"{class_name}Goal.msg": goal_content,
        f"{class_name}Result.msg": result_content,
        f"{class_name}Feedback.msg": feedback_content,
    }

    for filename, content in message_definitions.items():
        file_path = msg_dir / filename
        file_path.write_text(content)

    send_goal_content = (
        f"{class_name}Goal goal\n"
        + "unique_identifier_msgs/UUID goal_id\n"
        + "---\n"
        + "bool accepted\n"
        + "builtin_interfaces/Time stamp"
    )
    file_path = srv_dir / f"{class_name}SendGoal.srv"
    file_path.write_text(send_goal_content)

    get_result_content = (
        "unique_identifier_msgs/UUID goal_id\n"
        + "---\n"
        + f"{class_name}Result result\n"
        + "uint8 status"
    )
    file_path = srv_dir / f"{class_name}GetResult.srv"
    file_path.write_text(get_result_content)

    feedback_message_content = (
        f"{class_name}Feedback feedback\n" + "unique_identifier_msgs/UUID goal_id"
    )
    file_path = msg_dir / f"{class_name}FeedbackMessage.msg"
    file_path.write_text(feedback_message_content)


def create_message_file(msg_file, project_directory, install_dir):
    """
    Create a message file based on the template, replacing '@@MESSAGE_NAME@@' with the message file name.
    The file is saved in <g.script_directory>/include/<project_directory>/msg.
    """
    template_path = os.path.join(g.script_directory, "templates", "MessageTemplate.hpp")

    # Extract the project name from the project directory path
    project_name = os.path.basename(project_directory)

    # Determine the target directory in include/<project_name>/msg
    include_project_msg_dir = os.path.join(
        g.script_directory, "generated", "include", project_name, "msg"
    )
    destination_file = os.path.join(install_dir, "messages", project_name, "msg", "")
    os.makedirs(destination_file, exist_ok=True)
    shutil.copy2(msg_file, destination_file)

    # Delete the entire include directory before generating new files
    os.makedirs(include_project_msg_dir, exist_ok=True)  # Recreate it

    # Read the template
    with open(template_path, "r") as template_file:
        template_content = template_file.read()

    # Replace the placeholder with the message file name
    message_name = os.path.basename(msg_file).replace(".msg", "")
    class_name = message_name.replace("_", "")
    message_content = template_content.replace("@@MESSAGE_NAME@@", class_name)
    message_content = message_content.replace("@@PROJECT_NAME@@", project_name)

    # Read the message file and process its contents
    with open(msg_file, "r") as msg_file_content:
        lines = msg_file_content.readlines()

    includes = []
    members = []
    buffer_members = []
    buffer_size = []

    for line in lines:
        line = line.strip()

        # Ignore comments by splitting at '#' and taking the part before it
        line = line.split("#", 1)[0].strip()

        # Skip empty lines
        if not line:
            continue

        parts = line.split()
        parts_in_two = line.split(" ", 1)

        if len(parts) < 4 and "=" not in parts_in_two[1]:
            initial_value = ""
            if len(parts) == 3:
                data_type, data_name, initial_value = parts
            else:
                data_type, data_name = parts

            # Transform the data type for arrays
            transformed_type, base_type, subproject_path, found_type = (
                transform_data_type(data_type, project_name)
            )
            data_name = re.sub(
                r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))",
                "_",
                data_name,
            ).lower()
            data_name = data_name.replace("__", "_")

            # Check if the type is a known message type (not a primitive)
            if not found_type:
                # Use the preferred include format with relative path
                if not subproject_path:
                    subproject_path = project_name

                if data_type != "Header":
                    snake_str = re.sub(
                        r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))",
                        "_",
                        base_type,
                    ).lower()
                    snake_str = snake_str.replace("__", "_")
                    includes.append(
                        f'#include "../../{subproject_path}/msg/{snake_str}.hpp"'
                    )
                else:
                    includes.append(f'#include "../../std_msgs/msg/header.hpp"')

            members.append(f"using _{data_name}_type = {transformed_type};")
            if len(parts) == 3:
                members.append(f"{transformed_type} {data_name} = {initial_value};")
            else:
                members.append(f"{transformed_type} {data_name};")
            buffer_members.append(data_name)

            is_vector = transformed_type.startswith("std::vector")
            if is_vector or transformed_type.startswith("std::array"):
                buffer_size.append(
                    build_sequence_size_entry(is_vector, base_type, data_name, "")
                )
            else:
                if transformed_type in STRING_TYPES:
                    string_size_expr = build_string_size_expr(
                        transformed_type, data_name
                    )
                    buffer_size.append(
                        f"temp += sizeof(uint32_t) + {string_size_expr};"
                    )
                elif (
                    transformed_type in TYPE_MAPPING.values()
                    and transformed_type != "std::string"
                    and transformed_type != "std::u16string"
                ):
                    buffer_size.append(f"temp += sizeof({data_name});")
                else:
                    buffer_size.append(f"temp += {data_name}.getSize();")

        elif "=" in line:
            parts = line.split(" ", 1)
            members.append(f"static constexpr {TYPE_MAPPING[parts[0]]} {parts[1]};")

    # Insert includes and members into the template
    message_content = message_content.replace("@@INCLUDE_PATH@@", "\n".join(includes))
    message_content = message_content.replace("@@MEMBERS@@", "\n  ".join(members))
    message_content = message_content.replace(
        "@@BUFFER_SIZE_EXPRESSION@@", "\n  ".join(buffer_size)
    )

    set_buffer_member_string = ""
    get_buffer_member_string = ""
    equal_buffer_member_string = ""

    for bm in buffer_members:
        set_buffer_member_string += f"::raisin::setBuffer(buffer, {bm});\n"

    for bm in buffer_members:
        get_buffer_member_string += f"temp = ::raisin::getBuffer(temp, {bm});\n"

    for bm in buffer_members:
        equal_buffer_member_string += f"&& this->{bm} == other.{bm} \n"

    message_content = message_content.replace(
        "@@SET_BUFFER_MEMBERS@@", set_buffer_member_string
    )
    modified_set_buffer_member_string = "\n".join(
        "buffer = " + line for line in set_buffer_member_string.splitlines()
    )
    message_content = message_content.replace(
        "@@SET_BUFFER_MEMBERS2@@", modified_set_buffer_member_string
    )
    message_content = message_content.replace(
        "@@GET_BUFFER_MEMBERS@@", get_buffer_member_string
    )
    message_content = message_content.replace(
        "@@EQUAL_BUFFER_MEMBERS@@", equal_buffer_member_string
    )

    # Create the message file in the <g.script_directory>/include/<project_directory>/msg directory
    snake_str = re.sub(
        r"(?<!^)(?=[A-Z][a-z]|(?<=[a-z])[A-Z]|(?<=[0-9])(?=[A-Z]))", "_", message_name
    ).lower()
    snake_str = snake_str.replace("__", "_")
    output_path = os.path.join(include_project_msg_dir, f"{snake_str}.hpp")

    with open(output_path, "w") as output_file:
        output_file.write(message_content)

    # print(f"Created message file: {output_path}")


def get_ubuntu_version():
    with open("/etc/os-release") as f:
        for line in f:
            if "VERSION=" in line:
                version = line.split("=")[1].strip().strip('"')
                match = re.search(r"(\d+\.\d+)", version)
                if match:
                    return match.group(1)
    return None


def get_packages_to_ignore():
    """
    Gets packages to ignore from multiple sources:
    1. configuration_setting.yaml (raisin_ignore section)
    2. packages_to_ignore file (for backward compatibility)
    Returns a combined list of packages to ignore.
    """
    ignore_packages = []

    # Get packages from configuration_setting.yaml
    try:
        _, _, _, config_ignore, _ = load_configuration()
        ignore_packages.extend(config_ignore)
    except Exception:
        pass  # If configuration loading fails, continue with file-based approach

    # Get packages from RAISIN_IGNORE file (backward compatibility)
    try:
        # Get the absolute path of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Construct the full path to 'RAISIN_IGNORE'
        file_path = os.path.join(script_dir, "RAISIN_IGNORE")

        # Read the file and add its lines to the list
        with open(file_path, "r") as file:
            file_lines = [line.strip() for line in file.readlines()]
            ignore_packages.extend(file_lines)

    except FileNotFoundError:
        pass  # File doesn't exist, that's okay
    except Exception as e:
        raise Exception(f"An error occurred while reading RAISIN_IGNORE file: {e}")

    # Remove duplicates while preserving order
    return list(dict.fromkeys(ignore_packages))


def get_repos_to_ignore():
    """
    Gets repositories to ignore from configuration_setting.yaml.

    Returns:
        list: Names of src/ subdirectories to skip entirely.
    """
    try:
        _, _, _, _, repos_to_ignore = load_configuration()
        return repos_to_ignore or []
    except Exception:
        return []


def _print_ignore_lists(packages_to_ignore, repos_to_ignore):
    """
    Display the currently configured package/repo ignore lists.
    """

    def format_list(items):
        return ", ".join(sorted(items)) if items else "none"

    click.echo(
        f"🚫 packages_to_ignore: {format_list(packages_to_ignore)} | "
        f"repos_to_ignore: {format_list(repos_to_ignore)}"
    )


def _discover_pure_cmake_projects(
    package_name, packages_to_ignore=None, repos_to_ignore=None
):
    """
    Read release.yaml files to find pure CMake projects that should be built up front.
    """
    packages_to_ignore = set(packages_to_ignore or [])
    repo_ignore_set = set(repos_to_ignore or [])
    src_root = Path(g.script_directory) / "src"
    if not src_root.is_dir():
        return []

    if package_name:
        repo_dirs = (
            [src_root / package_name] if (src_root / package_name).is_dir() else []
        )
        if not repo_dirs:
            click.echo(
                f"⚠️  pure_cmake: package '{package_name}' not found under src/. Skipping pure_cmake scan.",
                err=True,
            )
            return []
    else:
        repo_dirs = [p for p in src_root.iterdir() if p.is_dir()]

    projects = []

    for repo_dir in repo_dirs:
        repo_name = repo_dir.name
        if repo_ignore_set and repo_name in repo_ignore_set:
            continue

        release_yaml = repo_dir / "release.yaml"
        if not release_yaml.is_file():
            continue

        try:
            with open(release_yaml, "r", encoding="utf-8") as f:
                release_info = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(f"⚠️  Warning: Could not parse {release_yaml}: {e}")
            continue

        pure_cmake_entries = release_info.get("pure_cmake") or []
        if not pure_cmake_entries:
            continue
        if not isinstance(pure_cmake_entries, list):
            print(
                f"⚠️  Warning: 'pure_cmake' in {release_yaml} must be a list. Skipping."
            )
            continue

        for project in pure_cmake_entries:
            if not project or project in packages_to_ignore:
                continue

            project_dir = repo_dir / project
            if not project_dir.is_dir():
                print(
                    f"⚠️  pure_cmake project '{project}' listed in {release_yaml} not found at {project_dir}"
                )
                continue

            projects.append((repo_name, project, project_dir))

    return projects


def build_pure_cmake_projects(
    install_dir, build_type, package_name, packages_to_ignore=None, repos_to_ignore=None
):
    """
    Build pure CMake projects in both debug and release dirs and install them to install_dir.
    """

    projects = _discover_pure_cmake_projects(
        package_name, packages_to_ignore, repos_to_ignore
    )
    if not projects:
        return []

    install_prefix = Path(g.script_directory) / install_dir
    print(f"🏗️  Building {len(projects)} pure CMake project(s) into: {install_prefix}")

    built = set()
    for build_type_token, cmake_build_type in (
        ("debug", "Debug"),
        ("release", "Release"),
    ):
        build_root = (
            Path(g.script_directory) / f"cmake-build-{build_type_token}" / "pure_cmake"
        )
        for repo_name, project_name, source_dir in projects:
            build_dir = build_root / project_name
            delete_directory(build_dir)
            build_dir.mkdir(parents=True, exist_ok=True)
            print(f"  -> {project_name} (from {repo_name}) [{cmake_build_type}]")

            try:
                if platform.system().lower() == "windows":
                    cmake_command = [
                        "cmake",
                        "-S",
                        str(source_dir),
                        "-B",
                        str(build_dir),
                        f"-DCMAKE_INSTALL_PREFIX={install_prefix}",
                        f"-DCMAKE_TOOLCHAIN_FILE={Path(g.script_directory) / 'vcpkg/scripts/buildsystems/vcpkg.cmake'}",
                        f"-DCMAKE_BUILD_TYPE={cmake_build_type}",
                        "-DBUILD_SHARED_LIBS=ON",
                    ]
                    if g.ninja_path:
                        cmake_command.extend(
                            ["-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={g.ninja_path}"]
                        )
                    elif shutil.which("ninja"):
                        cmake_command.extend(["-G", "Ninja"])
                    subprocess.run(
                        cmake_command, check=True, text=True, env=g.developer_env
                    )
                    subprocess.run(
                        [
                            "cmake",
                            "--build",
                            str(build_dir),
                            "--config",
                            cmake_build_type,
                            "--parallel",
                        ],
                        check=True,
                        text=True,
                        env=g.developer_env,
                    )
                    subprocess.run(
                        [
                            "cmake",
                            "--install",
                            str(build_dir),
                            "--config",
                            cmake_build_type,
                        ],
                        check=True,
                        text=True,
                        env=g.developer_env,
                    )
                else:
                    cmake_command = [
                        "cmake",
                        "-S",
                        str(source_dir),
                        "-B",
                        str(build_dir),
                        "-G",
                        "Ninja",
                        f"-DCMAKE_BUILD_TYPE={cmake_build_type}",
                        f"-DCMAKE_INSTALL_PREFIX={install_prefix}",
                        "-DBUILD_SHARED_LIBS=ON",
                    ]
                    subprocess.run(cmake_command, check=True, text=True)
                    core_count = max(1, (os.cpu_count() or 2) // 2)
                    subprocess.run(
                        [
                            "cmake",
                            "--build",
                            str(build_dir),
                            "--target",
                            "install",
                            "--",
                            f"-j{core_count}",
                        ],
                        check=True,
                        text=True,
                    )
                built.add(project_name)
            except subprocess.CalledProcessError as e:
                raise SystemExit(
                    f"❌ Failed to build pure_cmake project '{project_name}' (repo: {repo_name})."
                ) from e

    return list(built)


def find_git_repos(base_dir):
    """
    Recursively search for directories that contain a .git folder.
    Returns a list of paths that are Git repositories.
    """
    git_repos = []
    for root, dirs, _ in os.walk(base_dir):
        if ".git" in dirs:
            git_repos.append(root)
            # Prevent descending into this repository's subdirectories.
            dirs.clear()
    return git_repos


def install_development_tools():
    """
    Install development tools (clang-format, pre-commit) if not already installed.
    """
    print("Checking and installing development tools...")

    # Check if clang-format is installed
    try:
        subprocess.run(["clang-format", "--version"], capture_output=True, check=True)
        print("✅ clang-format is already installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Installing clang-format...")
        try:
            # Install clang-format based on the system
            if platform.system() == "Linux":
                # Try apt first (Ubuntu/Debian)
                try:
                    if is_root():
                        subprocess.run(["apt", "update"], check=True)
                        subprocess.run(
                            ["apt", "install", "-y", "clang-format"], check=True
                        )
                    else:
                        subprocess.run(["sudo", "apt", "update"], check=True)
                        subprocess.run(
                            ["sudo", "apt", "install", "-y", "clang-format"], check=True
                        )
                    print("✅ clang-format installed via apt")
                except subprocess.CalledProcessError:
                    # Try snap as fallback
                    try:
                        if is_root():
                            subprocess.run(
                                ["snap", "install", "clang-format"], check=True
                            )
                        else:
                            subprocess.run(
                                ["sudo", "snap", "install", "clang-format"], check=True
                            )
                        print("✅ clang-format installed via snap")
                    except subprocess.CalledProcessError:
                        print(
                            "❌ Failed to install clang-format. Please install manually."
                        )
            else:
                print(
                    "❌ Automatic clang-format installation not supported on this platform. Please install manually."
                )
        except Exception as e:
            print(f"❌ Error installing clang-format: {str(e)}")

        # Check if pre-commit is installed
    pre_commit_installed = False

    # Try system Python first (for git hooks)
    try:
        result = subprocess.run(
            ["/usr/bin/python3", "-m", "pre_commit", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            print("✅ pre-commit is already installed (system Python)")
            pre_commit_installed = True
    except Exception:
        pass

    # Try direct command if system Python doesn't work
    if not pre_commit_installed:
        try:
            result = subprocess.run(
                ["pre-commit", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                print("✅ pre-commit is already installed")
                pre_commit_installed = True
        except Exception:
            pass

    # Try current Python module if direct command failed
    if not pre_commit_installed:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pre_commit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                print("✅ pre-commit is already installed (python module)")
                pre_commit_installed = True
        except Exception:
            pass

    if not pre_commit_installed:
        print("Installing pre-commit...")
        try:
            # Try to install pre-commit to system Python first (for git hooks)
            # Check if current Python is already system Python3
            commands = ["/usr/bin/python3", "-m", "pip", "install", "pre-commit"]
            if not is_root():
                commands.insert(0, "sudo")
            if sys.executable == "/usr/bin/python3":
                commands.append("--break-system-packages")
            subprocess.run(commands, check=True)
            print("✅ pre-commit installed to system Python via pip")
        except subprocess.CalledProcessError:
            try:
                # Fallback to current Python environment
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "pre-commit"], check=True
                )
                print("✅ pre-commit installed via pip")
            except subprocess.CalledProcessError:
                try:
                    # Try with pip3 as fallback
                    subprocess.run(["pip3", "install", "pre-commit"], check=True)
                    print("✅ pre-commit installed via pip3")
                except subprocess.CalledProcessError:
                    print(
                        "❌ Failed to install pre-commit. Please install manually: sudo /usr/bin/python3 -m pip install pre-commit"
                    )


def get_commit_hash(repo_path):
    """
    Returns the current commit hash (HEAD) for the repository at repo_path.
    Uses the git command-line tool.
    """
    try:
        commit_hash = (
            subprocess.check_output(
                ["git", "-C", repo_path, "rev-parse", "HEAD"], stderr=subprocess.STDOUT
            )
            .decode("utf-8")
            .strip()
        )
        return commit_hash
    except subprocess.CalledProcessError as e:
        print(
            f"❌ Error getting commit hash for {repo_path}:\n{e.output.decode('utf-8')}"
        )
        return None


def read_existing_data(file_path):
    """
    Reads an existing file and returns a dictionary mapping repository names
    to commit hashes.
    """
    data = {}
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    repo_name = parts[0]
                    commit_hash = parts[1]
                    data[repo_name] = commit_hash
    return data


def write_data(file_path, data):
    """
    Writes the data (a dict of repo names to commit hashes) to the file.
    """
    with open(file_path, "w") as f:
        for repo, commit in data.items():
            f.write(f"{repo} {commit}\n")


def copy_resource(install_dir):
    target_dir = "resource"
    for root, dirs, files in os.walk(os.path.join(Path.home(), ".raisin")):

        # Check if the directory contains the target g.architecture subdirectory
        if target_dir in dirs:

            source_dir = os.path.join(root, target_dir)
            dest_dir = os.path.join(
                g.script_directory,
                install_dir,
                "resource",
                os.path.basename(root),
                target_dir,
            )

            for item in os.listdir(source_dir):
                s = os.path.join(source_dir, item)
                d = os.path.join(dest_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)


def deploy_install_packages():
    """
    Finds and copies packages that match the current system's OS and g.architecture.

    This function scans 'release/install' for packages matching the pattern
    '{target}/{g.os_type}/{g.architecture}/{build_type}'. It only considers packages
    where {g.os_type} and {g.architecture} match the current system. The contents
    of each valid package are copied into a corresponding directory structure at
    '{g.script_directory}/install/{target}/{g.os_type}/{g.architecture}', merging the
    contents from different build types (e.g., 'release', 'debug').

    Args:
        g.script_directory (str): The absolute path to the base directory.
    """

    repos_to_ignore = set(get_repos_to_ignore())

    # Create a glob pattern to find all build directories for the current system
    # e.g., .../release/install/*/linux/x86_64/*
    source_pattern = os.path.join(
        g.script_directory,
        "release",
        "install",
        "*",
        g.os_type,
        g.os_version,
        g.architecture,
        "*",
    )

    # Find all source directories that match
    found_source_dirs = glob.glob(source_pattern)

    if not found_source_dirs:
        print(
            f"🤷 No installed packages found for the current system ({g.os_type}/{g.os_version}/{g.architecture})."
        )
        return

    print(
        f"🚀 Deploying installed packages for system: {g.os_type}/{g.os_version}/{g.architecture}"
    )
    deployed_targets = set()

    try:
        for source_dir in found_source_dirs:
            if not os.path.isdir(source_dir):
                continue

            # Use pathlib to easily get the 'target' name from the path
            # The path is .../install/{target}/{os}/{g.os_version}/{arch}/{build_type}
            p = Path(source_dir)
            target_name = p.parents[3].name
            local_src_dir = Path(g.script_directory) / "src" / target_name
            if local_src_dir.is_dir():
                repo_name = get_repo_name_from_path(local_src_dir) or target_name
                if repo_name not in repos_to_ignore:
                    continue

            final_dest_dir = os.path.join(g.script_directory, "install")
            generated_dest_dir = os.path.join(g.script_directory, "generated")

            # Print the target-specific message only once
            if target_name not in deployed_targets:
                print(f"  -> Deploying target '{target_name}' to: {final_dest_dir}")
                deployed_targets.add(target_name)

            release_yaml_path = p / "release.yaml"
            if release_yaml_path.is_file():
                try:
                    with open(release_yaml_path, "r") as f:
                        release_data = yaml.safe_load(f)
                        # Ensure data was loaded and is a dictionary
                        if release_data and isinstance(release_data, dict):
                            # Safely get the list of dependencies, default to empty list
                            dependencies = release_data.get("g.vcpkg_dependencies", [])
                            if dependencies and isinstance(dependencies, list):
                                # Use set.update() to add all items from the list
                                g.vcpkg_dependencies.update(dependencies)
                except yaml.YAMLError as ye:
                    print(f"    - ⚠️ Warning: Could not parse {release_yaml_path}: {ye}")
                except IOError as ioe:
                    print(f"    - ⚠️ Warning: Could not read {release_yaml_path}: {ioe}")

            # Copy contents, merging files from different build_types
            shutil.copytree(source_dir, final_dest_dir, dirs_exist_ok=True)

            # Make all copied files executable
            bin_path = os.path.join(final_dest_dir, "bin")
            if os.path.exists(bin_path):
                for root, dirs, files in os.walk(bin_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        os.chmod(file_path, 0o755)

            if (p / "generated").is_dir():
                shutil.copytree(p / "generated", generated_dest_dir, dirs_exist_ok=True)

            if (p / "install_dependencies.sh").is_file():
                os.makedirs(
                    Path(g.script_directory) / "install/dependencies" / target_name,
                    exist_ok=True,
                )
                shutil.copy(
                    p / "install_dependencies.sh",
                    Path(g.script_directory)
                    / "install/dependencies"
                    / target_name
                    / "install_dependencies.sh",
                )

        if deployed_targets:
            print(f"\n✅ Successfully deployed {deployed_targets} target(s).")

    except Exception as e:
        print(f"❌ An error occurred during deployment: {e}")


def collect_src_vcpkg_dependencies(repos_to_ignore=None):
    """
    Scans subdirectories in '{g.script_directory}/src' for 'release.yaml' files.

    For each 'release.yaml' found, it reads the file and checks for a
    'g.vcpkg_dependencies' node. If the node exists, its contents (a list of
    strings) are merged into a master set to collect all unique dependencies.

    Returns:
        set: A set containing all unique vcpkg dependency strings found.
    """
    src_path = Path(g.script_directory) / "src"
    repo_ignore_set = set(repos_to_ignore or [])
    if not src_path.is_dir():
        print(f"🤷 Source directory not found at: {src_path}")
        return

    print(f"🔍 Scanning for vcpkg dependencies in: {src_path}")

    # Iterate over each item in the 'src' directory
    for project_dir in src_path.iterdir():
        # Process only if the item is a directory
        if not project_dir.is_dir():
            continue
        if repo_ignore_set:
            repo_name = get_repo_name_from_path(project_dir)
            if repo_name and repo_name in repo_ignore_set:
                continue

        release_yaml_path = project_dir / "release.yaml"

        # Check if 'release.yaml' exists in the subdirectory
        if release_yaml_path.is_file():
            try:
                with open(release_yaml_path, "r") as f:
                    release_data = yaml.safe_load(f)

                    # Ensure data was loaded and is a dictionary
                    if release_data and isinstance(release_data, dict):
                        # Safely get the list of dependencies, defaulting to an empty list
                        dependencies = release_data.get("g.vcpkg_dependencies", [])

                        if dependencies and isinstance(dependencies, list):
                            print(
                                f"  -> Found {len(dependencies)} dependencies in '{project_dir.name}'"
                            )
                            # Merge the found dependencies into the main set
                            g.vcpkg_dependencies.update(dependencies)

            except yaml.YAMLError as e:
                print(f"  -> ⚠️ Error parsing YAML in '{project_dir.name}': {e}")
            except IOError as e:
                print(f"  -> ⚠️ Error reading file in '{project_dir.name}': {e}")

    return


def generate_vcpkg_json():
    """
    Reads a vcpkg.json template, replaces a placeholder with dependencies,
    and saves the new file.

    Args:
        g.script_directory (str): The absolute path to the script's directory.
        g.vcpkg_dependencies (set): A set of strings representing vcpkg package names.
    """
    # Define the template and output file paths
    script_path = Path(g.script_directory)
    template_path = script_path / "templates" / "vcpkg.json"
    output_path = script_path / "vcpkg.json"

    # --- 1. Format the dependencies ---
    # Convert the set of dependencies into a single, comma-separated string
    # where each item is enclosed in double quotes.
    # e.g., {'fmt', 'spdlog'} -> '"fmt", "spdlog"'
    deps_string = ", ".join(f'"{dep}"' for dep in sorted(list(g.vcpkg_dependencies)))

    try:
        # --- 2. Read the template file ---
        print(f"Reading template from: {template_path}")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

        # --- 3. Replace the placeholder ---
        new_content = template_content.replace("@@DEP@@", deps_string)

        # --- 4. Write to the output file ---
        # Using "w" mode will create the file or overwrite it if it already exists.
        print(f"Writing new vcpkg.json to: {output_path}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        print("✅ Successfully generated vcpkg.json.")

    except FileNotFoundError:
        print(f"❌ Error: Template file not found at {template_path}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def guard_require_version_bump_for_src_packages():
    """
    Enforce:
      1) local src version == latest non-prerelease release version, AND
      2) (release commit != HEAD) OR (release commit == HEAD AND worktree dirty)
    → Raise SystemExit with a clear error asking to bump the version.
    """
    script_dir = Path(g.script_directory)
    src_dir = script_dir / "src"

    repositories, tokens, user_type, _, repos_to_ignore = load_configuration()
    repo_ignore_set = set(repos_to_ignore or [])

    if not src_dir.is_dir():
        return  # nothing to check

    violations = []

    for pkg_dir in sorted([p for p in src_dir.iterdir() if p.is_dir()]):
        if repo_ignore_set and pkg_dir.name in repo_ignore_set:
            continue
        package_name = pkg_dir.name
        release_yaml = pkg_dir / "release.yaml"
        if not release_yaml.is_file():
            continue

        # Local version
        try:
            with open(release_yaml, "r", encoding="utf-8") as f:
                info = yaml.safe_load(f) or {}
            local_version = "v" + str(info.get("version", "")).strip()
            if not local_version:
                continue  # nothing to compare
        except Exception:
            continue

        slug = _repo_slug_from_cfg(package_name, repositories)
        if not slug:
            continue
        owner, repo = slug

        token = tokens.get(owner) or tokens.get("github.com") or None
        latest = None
        try:
            latest = _get_latest_nonprerelease_release(owner, repo, token)
        except Exception:
            # If we cannot query, do not block setup; just continue.
            continue

        if not latest:
            continue

        latest_tag = (latest.get("tag_name") or "").strip()

        # Normalize tags in case tags are like "v1.2.3"
        def norm(v):
            return v[1:] if v.startswith("v") else v

        if norm(latest_tag) != norm(local_version):
            continue  # versions differ → OK, no guard trips

        # Compare commits
        latest_commit_in_body = _extract_commit_from_body(latest.get("body") or "")
        local_commit = get_commit_hash(str(pkg_dir))
        dirty = _is_worktree_dirty(str(pkg_dir))

        if (latest_commit_in_body != local_commit) or (
            latest_commit_in_body == local_commit and dirty
        ):
            # Build a helpful message for this package
            details = []
            details.append(f"version={local_version}")
            details.append(f"latest_release_tag={latest_tag}")
            details.append(f"release_commit={latest_commit_in_body or 'N/A'}")
            details.append(f"local_commit={local_commit or 'N/A'}")
            details.append(f"worktree_dirty={dirty}")
            violations.append(
                {
                    "package": package_name,
                    "version": local_version,
                    "latest_tag": latest_tag,
                    "release_commit": latest_commit_in_body or "N/A",
                    "local_commit": local_commit or "N/A",
                    "dirty": dirty,
                }
            )

    if violations:
        # --- pretty, colored output ---
        BOLD = "\033[1m"
        RESET = Colors.RESET

        def short_sha(s: Optional[str]) -> str:
            s = s or "N/A"
            return s[:10]

        title = f"{Colors.RED}{BOLD}❌ Version bump required before setup{RESET}"
        subtitle = (
            "Your local source version matches the latest stable release, "
            "but commits differ or the working tree has changes.\n"
            "Please bump the version in:  src/<package>/release.yaml"
        )

        headers = [
            "PACKAGE",
            "VERSION",
            "LATEST TAG",
            "RELEASE COMMIT",
            "LOCAL COMMIT",
            "DIRTY",
        ]

        def w(text):
            return get_display_width(str(text))

        # compute column widths (use 10-char commit display)
        col_widths = [w(h) for h in headers]
        for row in violations:
            col_widths[0] = max(col_widths[0], w(row["package"]))
            col_widths[1] = max(col_widths[1], w(row["version"]))
            col_widths[2] = max(col_widths[2], w(row["latest_tag"]))
            col_widths[3] = max(col_widths[3], w(short_sha(row["release_commit"])))
            col_widths[4] = max(col_widths[4], w(short_sha(row["local_commit"])))
            col_widths[5] = max(col_widths[5], w(str(row["dirty"])))

        def fmt_row(vals):
            cells = []
            for i, v in enumerate(vals):
                s = str(v)
                pad = col_widths[i] - w(s)
                cells.append(s + " " * pad)
            return " | ".join(cells)

        header_line = fmt_row(headers)
        sep = "-" * get_display_width(header_line)

        body_lines = []
        for row in violations:
            body_lines.append(
                fmt_row(
                    [
                        row["package"],
                        row["version"],
                        row["latest_tag"],
                        short_sha(row["release_commit"]),
                        short_sha(row["local_commit"]),
                        row["dirty"],
                    ]
                )
            )

        msg = (
            f"\n{title}\n"
            f"{Colors.YELLOW}{subtitle}{RESET}\n\n"
            f"{header_line}\n{sep}\n" + "\n".join(body_lines) + "\n"
        )

        print(msg)
        sys.exit(1)


def setup(package_name="", build_type="", build_dir="", build_test_enabled=None):
    """
    setup function to find project directories, msg, and srv files and generate message and service files.
    """

    if package_name == "":
        src_dir = "src"
        install_dir = "install"
    else:
        src_dir = "src/" + package_name
        install_dir = f"release/install/{package_name}/{g.os_type}/{g.os_version}/{g.architecture}/{build_type}"

    delete_directory(
        os.path.join(g.script_directory, "generated")
    )  # Delete the whole 'include' directory
    delete_directory(Path(g.script_directory) / install_dir)
    os.makedirs(Path(g.script_directory) / install_dir, exist_ok=True)

    if build_dir:
        os.makedirs(build_dir, exist_ok=True)

    packages_to_ignore = get_packages_to_ignore()
    repos_to_ignore = get_repos_to_ignore()

    deploy_install_packages()

    guard_src_repo_release_yaml_dependencies(packages_to_ignore, repos_to_ignore)

    pure_cmake_built = build_pure_cmake_projects(
        install_dir,
        build_type,
        package_name,
        packages_to_ignore,
        repos_to_ignore,
    )
    if pure_cmake_built:
        packages_to_ignore = list(
            dict.fromkeys(list(packages_to_ignore) + pure_cmake_built)
        )
    _print_ignore_lists(packages_to_ignore, repos_to_ignore)

    action_files = find_interface_files(
        ["src"], ["action"], packages_to_ignore, repos_to_ignore
    )[0]

    project_directories = find_project_directories(
        [src_dir], install_dir, packages_to_ignore, repos_to_ignore
    )

    # Handle .action files
    for action_file in action_files:
        create_action_file(action_file, Path(action_file).parent.parent, install_dir)

    msg_files, srv_files = find_interface_files(
        ["src", "temp"], ["msg", "srv"], packages_to_ignore, repos_to_ignore
    )

    # Handle .msg files
    for msg_file in msg_files:
        create_message_file(msg_file, Path(msg_file).parent.parent, install_dir)

    # Handle .srv files
    for srv_file in srv_files:
        create_service_file(srv_file, Path(srv_file).parent.parent, install_dir)

    # Update the CMakeLists.txt based on the template
    if build_test_enabled is None:
        build_test_enabled = True
    update_cmake_file(project_directories, build_dir, bool(build_test_enabled))

    if package_name == "":  # this means we are not in the release mode
        copy_resource(install_dir)

    os.makedirs(os.path.join(g.script_directory, "generated/include"), exist_ok=True)
    shutil.copy(
        os.path.join(g.script_directory, "templates", "raisin_serialization_base.hpp"),
        os.path.join(g.script_directory, "generated/include"),
    )

    # create release tag
    install_release_file = Path(g.script_directory) / "install" / "release.txt"

    # Read existing data if the file already exists.
    existing_data = read_existing_data(install_release_file)
    output_file = Path(g.script_directory) / install_dir / "release.txt"

    # Find Git repositories under the base directory.
    git_repos = find_git_repos(g.script_directory + "/src")
    git_repos.append(g.script_directory)
    new_data = {}

    if not git_repos:
        print("No Git repositories found.")
    else:
        for repo in git_repos:
            commit_hash = get_commit_hash(repo)
            if commit_hash:
                # Use just the folder name for the repository.
                repo_name = os.path.basename(repo)
                new_data[repo_name] = commit_hash
                print(f"✅ Found {repo_name}: {commit_hash}")

    # Merge: New data overwrites any duplicate repository names in existing data.
    merged_data = existing_data.copy()
    merged_data.update(new_data)

    # Write the merged result to the output file.
    write_data(output_file, merged_data)
    print(f"💾 Wrote git hash file: {output_file}")

    # copy raisin serialization base
    src_file = os.path.join(
        g.script_directory, "templates", "raisin_serialization_base.hpp"
    )
    dest_dir = os.path.join(g.script_directory, "generated", "include")

    os.makedirs(dest_dir, exist_ok=True)  # Ensure destination directory exists
    shutil.copy2(src_file, dest_dir)

    os.makedirs(Path(g.script_directory) / "install", exist_ok=True)

    # install generated files
    shutil.copytree(
        Path(g.script_directory) / "generated",
        Path(g.script_directory) / install_dir / "generated",
        dirs_exist_ok=True,
    )

    shutil.copy2(
        Path(g.script_directory) / "templates/install_dependencies.sh",
        Path(g.script_directory) / "install/install_dependencies.sh",
    )

    collect_src_vcpkg_dependencies(repos_to_ignore)
    generate_vcpkg_json()
    click.secho("✅ Setup finished successfully.", fg="green")


def _repo_slug_from_cfg(
    package_name: str, repositories: Dict[str, Any]
) -> Optional[Tuple[str, str]]:
    """Return (owner, repo) for a package from configuration_setting.yaml or None."""
    info = repositories.get(package_name)
    if not info or "url" not in info:
        return None
    m = re.search(r"git@github\.com:(.*?)/(.*?)\.git", info["url"])
    if not m:
        return None
    return m.group(1), m.group(2)


def _get_latest_nonprerelease_release(
    owner: str, repo: str, token: Optional[str]
) -> Optional[Dict[str, Any]]:
    """
    Return the latest *non-prerelease* GitHub release object (dict) or None.
    """
    session = requests.Session()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    resp = session.get(
        f"https://api.github.com/repos/{owner}/{repo}/releases",
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()
    releases = resp.json()
    # Sort by created_at desc and filter prerelease==False
    stable = [r for r in releases if not r.get("prerelease")]
    if not stable:
        return None

    # Prefer the greatest semver tag if tags are semantic, else fallback to created_at
    def tag_key(r):
        try:
            return parse_version(r.get("tag_name") or "0.0.0")
        except Exception:
            return parse_version("0.0.0")

    stable.sort(key=tag_key, reverse=True)
    return stable[0]


def _extract_commit_from_body(body: str) -> Optional[str]:
    """
    Pull a git commit hash (7-40 hex) from the release body; prefers 40-char SHA.
    """
    if not body:
        return None
    # Prefer full sha-1 first
    m = re.search(r"\b[0-9a-f]{40}\b", body, re.IGNORECASE)
    if m:
        return m.group(0)
    # else allow short SHAs (>=7 chars)
    m = re.search(r"\b[0-9a-f]{7,40}\b", body, re.IGNORECASE)
    return m.group(0) if m else None


def _is_worktree_dirty(repo_path: str) -> bool:
    """True if there are uncommitted changes in repo_path."""
    out = _run_git_command(["git", "status", "--porcelain"], repo_path)
    return bool(out)
