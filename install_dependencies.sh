#!/usr/bin/env bash
# run_all_dependency_installers.sh
# ---------------------------------
# Purpose  : Search every immediate sub-directory of the directory
#            in which this script resides.
# Condition : If an install_dependencies.sh file exists, execute it.
# Execution : If the file is executable, run it directly.
#             Otherwise, launch it via bash.
# Safety    : Stops at the first error thanks to `set -e`.

set -euo pipefail

# Absolute path to the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prevent globbing patterns from expanding to themselves when no match is found
shopt -s nullglob

# --- Setup ---
# Color codes for beautiful output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Automatically handle sudo prefix
SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

# Automatically handle pip flags for root
PIP_FLAGS=""
if [[ $EUID -eq 0 ]]; then
    PIP_FLAGS="--break-system-packages"
fi

echo -e "${YELLOW}Checking and installing core Python...${NC}"
echo "-------------------------------------------------"
if ! command -v python3 &> /dev/null || ! python3 -m pip --version &> /dev/null; then
    echo "Python3 or pip not found. Attempting installation..."
    if command -v apt-get &> /dev/null; then
        echo "Attempting to install with apt..."
        $SUDO apt-get update > /dev/null
        $SUDO apt-get install -y python3 python3-pip lsb-release
        echo -e "${GREEN}✅ Python 3 and pip installed via apt.${NC}"
    elif command -v dnf &> /dev/null; then
        echo "Attempting to install with dnf..."
        $SUDO dnf install -y python3 python3-pip redhat-lsb-core
        echo -e "${GREEN}✅ Python 3 and pip installed via dnf.${NC}"
    elif command -v pacman &> /dev/null; then
        echo "Attempting to install with pacman..."
        $SUDO pacman -S --noconfirm python python-pip lsb-release
        echo -e "${GREEN}✅ Python 3 and pip installed via pacman.${NC}"
    else
        echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install Python 3 and pip manually.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ Python 3 and pip are already installed.${NC}"
fi

echo -e "${YELLOW}Checking and installing development tools...${NC}"
echo "-------------------------------------------------"

# --- 1. Check and Install clang-format ---
echo "Checking for clang-format..."
if command -v clang-format &> /dev/null; then
    echo -e "${GREEN}✅ clang-format is already installed.${NC}"
else
    echo "clang-format not found. Attempting installation..."
    if [[ "$(uname)" == "Linux" ]]; then
        # Try apt first (Debian/Ubuntu)
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            if $SUDO apt-get update > /dev/null && $SUDO apt-get install -y clang-format; then
                echo -e "${GREEN}✅ clang-format installed via apt.${NC}"
            else
                echo -e "${RED}apt installation failed. Please check for errors and install manually.${NC}"
            fi
        # Fallback to snap
        elif command -v snap &> /dev/null; then
            echo "apt not found. Attempting to install with snap..."
            if $SUDO snap install clang-format --classic; then
                echo -e "${GREEN}✅ clang-format installed via snap.${NC}"
            else
                echo -e "${RED}❌ Failed to install clang-format with snap. Please install manually.${NC}"
            fi
        else
             echo -e "${RED}❌ Neither apt nor snap found. Please install clang-format manually.${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic clang-format installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"

# --- 2. Check and Install Ninja ---
echo "Checking for Ninja Build..."
if command -v ninja &> /dev/null; then
    echo -e "${GREEN}✅ Ninja is already installed.${NC}"
else
    echo "Ninja not found. Attempting installation..."
    # Linux Installation Logic
    if [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            $SUDO apt-get update > /dev/null && $SUDO apt-get install -y ninja-build
            echo -e "${GREEN}✅ Ninja installed via apt.${NC}"
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            $SUDO dnf install -y ninja-build
            echo -e "${GREEN}✅ Ninja installed via dnf.${NC}"
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            $SUDO pacman -S --noconfirm ninja
            echo -e "${GREEN}✅ Ninja installed via pacman.${NC}"
        else
            echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install Ninja manually.${NC}"
        fi
    # macOS Installation Logic
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install ninja
            echo -e "${GREEN}✅ Ninja installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install Ninja manually ('brew install ninja').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic Ninja installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"

# --- 3. Check and Install pre-commit ---
echo "Checking for pre-commit..."
# Check for pre-commit in common locations
if command -v pre-commit &> /dev/null || /usr/bin/python3 -m pre_commit --version &> /dev/null; then
    echo -e "${GREEN}✅ pre-commit is already installed.${NC}"
else
    echo "pre-commit not found. Attempting installation..."
    # Attempt 0: Try Linux installation
    # Linux Installation Logic
    if [[ "$(uname)" == "Linux" ]] && $SUDO apt install pre-commit; then
        echo -e "${GREEN}✅ pre-commit installed to system via apt.${NC}"
    # Attempt 1: System-wide install (most reliable for git hooks)
    elif $SUDO /usr/bin/python3 -m pip install $PIP_FLAGS pre-commit; then
        echo -e "${GREEN}✅ pre-commit installed to system Python via pip.${NC}"
    # Attempt 2: Current user install via `python3 -m pip` (safer fallback)
    elif python3 -m pip install --user pre-commit; then
        echo -e "${GREEN}✅ pre-commit installed for the current user via pip.${NC}"
        echo -e "${YELLOW}NOTE: Make sure '~/.local/bin' is in your shell's PATH.${NC}"
    # Attempt 3: Fallback to just `pip3`
    elif pip3 install --user pre-commit; then
        echo -e "${GREEN}✅ pre-commit installed for the current user via pip3.${NC}"
        echo -e "${YELLOW}NOTE: Make sure '~/.local/bin' is in your shell's PATH.${NC}"
    else
        echo -e "${RED}❌ All automatic installation attempts for pre-commit failed.${NC}"
        echo -e "${RED}Please install it manually, for example:${NC} sudo /usr/bin/python3 -m pip install pre-commit"
    fi
fi

# --- 4. Check and Install GitHub CLI (gh) ---
echo "Checking for GitHub CLI (gh)..."
if command -v gh &> /dev/null; then
    echo -e "${GREEN}✅ gh is already installed.${NC}"
else
    echo "gh not found. Attempting installation..."
    # Linux Installation Logic
    if [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            $SUDO apt-get update > /dev/null && $SUDO apt-get install -y gh
            echo -e "${GREEN}✅ gh installed via apt.${NC}"
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            $SUDO dnf install -y gh
            echo -e "${GREEN}✅ gh installed via dnf.${NC}"
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            $SUDO pacman -S --noconfirm github-cli
            echo -e "${GREEN}✅ gh installed via pacman.${NC}"
        else
            echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install gh manually.${NC}"
        fi
    # macOS Installation Logic
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install gh
            echo -e "${GREEN}✅ gh installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install gh manually ('brew install gh').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic gh installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"

# --- 5. Check and Install CMake ---
echo "Checking for CMake..."
if command -v cmake &> /dev/null; then
    echo -e "${GREEN}✅ CMake is already installed.${NC}"
else
    echo "CMake not found. Attempting installation..."
    # Linux Installation Logic
    if [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            $SUDO apt-get update > /dev/null && $SUDO apt-get install -y cmake
            echo -e "${GREEN}✅ CMake installed via apt.${NC}"
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            $SUDO dnf install -y cmake
            echo -e "${GREEN}✅ CMake installed via dnf.${NC}"
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            $SUDO pacman -S --noconfirm cmake
            echo -e "${GREEN}✅ CMake installed via pacman.${NC}"
        else
            echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install CMake manually.${NC}"
        fi
    # macOS Installation Logic
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install cmake
            echo -e "${GREEN}✅ CMake installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install CMake manually ('brew install cmake').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic CMake installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"
echo -e "${GREEN}Setup check complete. Now installing dependencies of each packages${NC}"

# cli dependency pip installation
pip3 install $PIP_FLAGS PyYAML Click requests packaging

# copy configuration_setting file
if [ -f "configuration_setting_example.yaml" ]; then
    cp -n configuration_setting_example.yaml configuration_setting.yaml
fi

# make install/install_dependencies.sh
python3 ./raisin.py setup

$SUDO bash install/install_dependencies.sh || {
  echo "Failed to install sub-project dependencies. Please check the output above for errors."
  exit 1
}
