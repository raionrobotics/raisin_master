# RAISIN: Raion System Installer

RAISIN is a Python-based build-system wrapper designed to simplify dependency management and project compilation for CMake-based projects at Raion Robotics. It automates the process of fetching dependencies, configuring the build environment, and compiling the source code.

---

## 📜 License and Disclaimer

This software is proprietary and is licensed under the terms detailed in the `LICENSE` file. **Its use is exclusively permitted for products and projects developed by or for Raion Robotics Inc.**

---

## ✅ Prerequisites

Before you begin, ensure your system meets the following requirements.

### Supported Operating Systems
* **Windows**: 10 / 11
* **Linux**: Ubuntu 22.04 / 24.04

### Dependencies

#### For Linux
The provided shell script automates the entire dependency installation process. Simply run:
```bash
sudo bash install_dependencies.sh
```

#### For Windows
You will need to manually install the following software. Please ensure that the executables for **Git**, **Git CLI**, and **Ninja** are available in your system's `Path` environment variable.

* [Python](https://www.python.org/downloads/) (version 3.8 or newer)
* [Git](https://git-scm.com/download/win)
* [Git CLI](https://github.com/cli/cli/releases)
* [Ninja](https://github.com/ninja-build/ninja/releases)
* [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) (with the "Desktop development with C++" workload)

### Project Initialization

Once the above dependencies are installed, complete the following steps in your terminal:

1.  **Initialize Git Submodules:** (Only for Windows) This project uses `vcpkg` as a git submodule for C++ package management in Windows.
    ```bash
    git submodule update --init
    ```

2.  **Install Required Python Packages:**
    ```bash
    pip3 install PyYAML packaging requests click
    ```

---

## 🚀 Getting Started

Follow these steps to configure and build your project.

### 1. Project Configuration

Create your local configuration file by copying the provided example.
```bash
cp configuration_setting_example.yaml configuration_setting.yaml
```
Next, open **`configuration_setting.yaml`** and edit the following fields:
* **`gh_token`**: Set this to the GitHub Personal Access Token provided to you by Raion Robotics.
* **`target_type`**: Set to `devel` for development builds.
* **`raisin_ignore`**: (Optional) Add the names of any packages you wish to exclude from the dependency resolution process.

### 2. Add Source Packages

Create a directory named `src` in the root of the repository. Clone any source code packages you are developing or contributing to inside this `src` directory.
```bash
mkdir src
cd src
git clone <your-package-repository>
```

### 3. Install Dependencies

Run the `install` command to let RAISIN resolve and install all necessary dependencies for the packages located in the `src` directory.
```bash
python3 raisin.py install <package_name>
```
For example:
```bash
# Install a specific package (release version by default)
python3 raisin.py install raisin_network

# Install debug version
python3 raisin.py install raisin_network --type debug

# Install multiple packages
python3 raisin.py install package1 package2 package3
```

### 4. Generate Build Files

Run the `setup` command to configure the CMake environment and generate interface files.
```bash
# Setup all packages
python3 raisin.py setup

# Setup specific packages
python3 raisin.py setup raisin_network
```

### 5. Build the Project

Use the `build` command to compile the project. You must specify the build type using `--type` (or `-t`).

```bash
# Build release version
python3 raisin.py build --type release

# Build debug version
python3 raisin.py build --type debug

# Build and install
python3 raisin.py build --type release --install

# Short form
python3 raisin.py build -t release -i

# Build specific target
python3 raisin.py build -t release raisin_network
```

Alternatively, advanced users can use standard CMake commands in the `cmake-build-debug/` or `cmake-build-release/` directories.

### 6. Additional Commands

#### Publish a Release
Build, package, and upload a release to GitHub:
```bash
# Publish release build
python3 raisin.py publish raisin_network

# Publish debug build
python3 raisin.py publish raisin_network --type debug
```

#### List Packages
View available packages:
```bash
# List local packages
python3 raisin.py index local

# List all remote packages on GitHub
python3 raisin.py index release

# List versions of a specific package
python3 raisin.py index release raisin_network
```

#### Git Operations
Manage multiple repositories:
```bash
# Show status of all repositories
python3 raisin.py git status

# Pull all repositories
python3 raisin.py git pull

# Pull from specific remote
python3 raisin.py git pull --remote upstream

# Fetch from a remote for all src repositories (default: origin)
python3 raisin.py git fetch --remote origin

# Checkout an existing branch across all repositories in src (skips if missing)
python3 raisin.py git checkout --branch feature-branch

# Setup git remotes
python3 raisin.py git setup origin:raionrobotics dev:yourusername
```

#### Get Help
View help for any command:
```bash
# Main help
python3 raisin.py --help
python3 raisin.py -h

# Command-specific help
python3 raisin.py build --help
python3 raisin.py publish -h
```

---

## 📚 Documentation

For more detailed information and API references, please visit our official documentation:

**[https://raionrobotics.com/documentation](https://raionrobotics.com/documentation)**
