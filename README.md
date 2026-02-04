# RAISIN: Raion System Installer

RAISIN is a Python-based build-system wrapper designed to simplify dependency management and project compilation for CMake-based projects at Raion Robotics. It automates the process of fetching dependencies, configuring the build environment, and compiling the source code.

---

## License and Disclaimer

This software is proprietary and is licensed under the terms detailed in the `LICENSE` file. **Its use is exclusively permitted for products and projects developed by or for Raion Robotics Inc.**

---

## Prerequisites

Before you begin, ensure your system meets the following requirements.

### Supported Operating Systems
* **Windows**: 10 / 11
* **Linux**: Ubuntu 22.04 / 24.04 (x86_64, ARM64)

### Dependencies

#### For Windows
You will need to manually install the following software. Please ensure that the executables for **Git**, **Git CLI**, and **Ninja** are available in your system's `Path` environment variable.

* [Python](https://www.python.org/downloads/) (version 3.8 or newer)
* [Git](https://git-scm.com/download/win)
* [Git CLI](https://github.com/cli/cli/releases)
* [Ninja](https://github.com/ninja-build/ninja/releases)
* [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) (with the "Desktop development with C++" workload)

Once the above dependencies are installed, complete the following steps in your terminal:

**Initialize Git Submodules:** This project uses `vcpkg` as a git submodule for C++ package management.
    ```bash
    git submodule update --init
    ```

---

## Getting Started

Follow these steps to configure and build your project.

### 1. Install RAISIN CLI and System Dependencies

Run the install command to set up the RAISIN command-line tool. This:
- Creates a Python virtual environment
- Installs system dependencies (Python, CMake, Ninja, clang-format, pre-commit, gh)
- Adds a shell function for auto-activation

```bash
./raisin --install
```

After installation, **restart your terminal** (or run `source ~/.bashrc`) to enable the `raisin` command.

> **Note:** The installer will prompt for sudo to install system dependencies. If you prefer to install them separately, you can run `sudo bash install_system_deps.sh` manually.

### 2. Project Configuration

Create your local configuration file by copying the provided example.
```bash
cp configuration_setting_example.yaml configuration_setting.yaml
```
Next, open **`configuration_setting.yaml`** and edit the following fields:
* **`gh_tokens`**: (Optional) GitHub Personal Access Token for each organization (e.g., `"raionrobotics": "ghp_your_token"`). Only needed for GitHub fallback or publishing to GitHub.
* **`user_type`**: Set to `"user"` for stable releases or `"devel"` for development builds.
* **`packages_to_ignore`**: (Optional) List of packages to exclude from the build process.
* **`repos_to_ignore`**: (Optional) List of repositories to exclude (uses prebuilt binaries instead).

### 3. OTA Server Configuration

RAISIN downloads packages from the OTA (Over-The-Air) server by default, with GitHub releases as fallback. The default endpoint is `https://raisin-ota-api.raionrobotics.com/api`.

```bash
# (Optional) Override the default OTA endpoint
export RAISIN_OTA_ENDPOINT="https://your-custom-ota-server.com/api"

# (Optional) Specify SSH key path for authentication
export RAISIN_SSH_KEY="~/.ssh/my_key"

# (Optional) Custom archive name prefix (default: raisin-robot)
export RAISIN_ARCHIVE_NAME="raisin-robot"
```

#### SSH Key Authentication

OTA authentication uses SSH key-based challenge-response. The following key types are supported:
- **Ed25519** (`id_ed25519`) - Recommended
- **ECDSA** (`id_ecdsa`) - nistp256, nistp384, nistp521 curves
- **RSA** (`id_rsa`)

If `RAISIN_SSH_KEY` is not set, RAISIN auto-detects existing keys in `~/.ssh/` in the order above.

> **Note:** Ensure your SSH public key is registered with the OTA server before using OTA features.

### 4. Add Source Packages

Create a directory named `src` in the root of the repository. Clone any source code packages you are developing or contributing to inside this `src` directory.
```bash
mkdir src
cd src
git clone <your-package-repository>
```

### 5. Install Release Packages

Run the `install` command to download packages from the OTA server (primary) or GitHub releases (fallback).

```bash
# Install from latest archive (default)
raisin install

# Install a specific package
raisin install raisin_network

# Install with specific version
raisin install raisin_network==1.1.0

# Install debug version
raisin install raisin_network --type debug

# Install both debug and release
raisin install raisin_network --all

# Install multiple packages
raisin install package1 package2 package3
```

#### Advanced Install Options

```bash
# Install from a specific archive version
raisin install --archive-version v2024.01

# Install packages at a specific timestamp (time-travel)
raisin install --at 2024-01-15
raisin install --at 2024-01-15T10:00:00Z

# Skip OTA and download directly from GitHub (for debugging)
raisin install --from-github

# Combine options
raisin install raisin_network --type debug --archive-version v2024.01
```

> **Note:** Packages are downloaded from the OTA server by default. Use `--from-github` to bypass OTA and download directly from GitHub releases (useful for debugging or when OTA is unavailable).

### 6. Install Package Dependencies

Run the package dependency installer to install package-specific dependencies (e.g., vcpkg packages, ROS packages, custom libraries).
```bash
sudo bash install_dependencies.sh
```

> **Note:** This script runs `install_dependencies.sh` files directly from source packages (`src/`) and release packages (`release/install/`).

### 7. Setup and Generate Build Files

Run the `setup` command to configure the CMake environment and generate interface files.
```bash
# Setup all packages
raisin setup

# Setup specific packages
raisin setup raisin_network
```

### 8. Build the Project

Use the `build` command to compile the project. You must specify the build type using `--type` (or `-t`).

```bash
# Build release version
raisin build --type release

# Build debug version
raisin build --type debug

# Build and install artifacts
raisin build --type release --install

# Short form
raisin build -t release -i

# Build specific target
raisin build -t release raisin_network
```

Alternatively, advanced users can use standard CMake commands in the `cmake-build-debug/` or `cmake-build-release/` directories.

### 9. Additional Commands

#### Publish a Release
Build, package, and upload a release to GitHub or OTA server:
```bash
# Publish to GitHub (default)
raisin publish raisin_network

# Publish only release build
raisin publish raisin_network --type release

# Publish only debug build
raisin publish raisin_network --type debug

# Publish to OTA server instead of GitHub
raisin publish raisin_network --upload-ota

# Dry run without uploading
raisin publish raisin_network --dry-run
```

> **Note:** Use `--upload-ota` to upload to the OTA server instead of GitHub. This requires `RAISIN_OTA_ENDPOINT` to be set.

#### List Packages
View available packages:
```bash
# List local packages
raisin index local

# List all remote packages on GitHub
raisin index release

# List versions of a specific package
raisin index release raisin_network
```

#### Git Operations
Manage multiple repositories:
```bash
# Show status of all repositories
raisin git status

# Pull all repositories
raisin git pull

# Pull from specific remote
raisin git pull --remote upstream

# Fetch from a remote for all src repositories (default: origin)
raisin git fetch --remote origin

# Checkout or create a branch across all repositories in src
raisin git checkout --branch feature-branch

# Delete a local branch across all repositories in src (use -f to force)
raisin git delete-branch --branch old-feature
raisin git delete-branch -b old-feature -f

# List local branches for all repositories in src
raisin git list-branches

# Push the current branch to the same branch name on a remote for all src repositories
raisin git push-current --remote origin

# Setup git remotes
raisin git setup origin:raionrobotics dev:yourusername
```

#### Get Help
View help for any command:
```bash
# Main help
raisin --help
raisin -h

# Command-specific help
raisin build --help
raisin publish -h
```

> **Note:** If you have multiple RAISIN repo clones, `raisin` prefers the clone that contains your current working directory (walks up to find `raisin.py`). You can also use `python3 raisin.py` directly if needed.

---

## Quick Reference: Workflow Summary

```bash
# 1. Install RAISIN CLI and system tools
./raisin --install

# 2. Configure your settings
cp configuration_setting_example.yaml configuration_setting.yaml
# Edit configuration_setting.yaml with your GitHub tokens (optional if using OTA)

# 3. (Optional) Configure OTA server
export RAISIN_OTA_ENDPOINT="https://your-ota-server.com/api"

# 4. Clone source packages
mkdir -p src && cd src
git clone <your-package-repository>
cd ..

# 5. Download release packages
raisin install                        # All packages from latest archive
raisin install <package_name>         # Specific package

# 6. Install package-specific dependencies
sudo bash install_dependencies.sh

# 7. Generate build files
raisin setup

# 8. Build
raisin build -t release
```

---

## Documentation

For more detailed information and API references, please visit our official documentation:

**[https://raionrobotics.com/documentation](https://raionrobotics.com/documentation)**
