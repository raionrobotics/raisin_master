#!/usr/bin/env bash
# install_system_deps.sh
# ----------------------
# Purpose  : Install system-level development tools required for RAISIN.
#            This includes: Python3, pip, venv, clang-format, ninja, pre-commit,
#            GitHub CLI (gh), CMake, Git LFS, vcstool, cppcheck, and gcovr.
# Usage    : Called by `./raisin --install` or run manually with sudo.
# Platform : Linux (apt, dnf, pacman) and macOS (Homebrew)

set -euo pipefail

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

# Install python venv separately with fallback handling
echo "Checking for Python venv..."
if python3 -m venv --help &> /dev/null 2>&1; then
    echo -e "${GREEN}✅ Python venv is already available.${NC}"
else
    echo "Python venv not found. Attempting installation..."
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if command -v apt-get &> /dev/null; then
        if $SUDO apt-get install -y python3-venv 2>/dev/null; then
            echo -e "${GREEN}✅ Python venv installed via apt.${NC}"
        elif $SUDO apt-get install -y "python${PY_VERSION}-venv" 2>/dev/null; then
            echo -e "${GREEN}✅ Python venv (python${PY_VERSION}-venv) installed via apt.${NC}"
        else
            echo -e "${YELLOW}⚠️ Could not install python3-venv. Some features may not work.${NC}"
        fi
    elif command -v dnf &> /dev/null; then
        $SUDO dnf install -y python3-venv 2>/dev/null || \
            echo -e "${YELLOW}⚠️ Could not install python3-venv. Some features may not work.${NC}"
    elif command -v pacman &> /dev/null; then
        $SUDO pacman -S --noconfirm python-venv 2>/dev/null || \
            echo -e "${YELLOW}⚠️ Could not install python-venv. Some features may not work.${NC}"
    fi
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
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            if brew install clang-format; then
                echo -e "${GREEN}✅ clang-format installed via Homebrew.${NC}"
            else
                echo -e "${RED}❌ Failed to install clang-format with Homebrew.${NC}"
            fi
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install clang-format manually ('brew install clang-format').${NC}"
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
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            if brew install pre-commit; then
                echo -e "${GREEN}✅ pre-commit installed via Homebrew.${NC}"
            else
                echo -e "${RED}❌ Failed to install pre-commit with Homebrew.${NC}"
            fi
        else
            echo -e "${RED}❌ Homebrew not found. Please install pre-commit manually ('brew install pre-commit').${NC}"
        fi
    elif [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null && $SUDO apt-get install -y pre-commit; then
            echo -e "${GREEN}✅ pre-commit installed to system via apt.${NC}"
        elif $SUDO /usr/bin/python3 -m pip install $PIP_FLAGS pre-commit; then
            echo -e "${GREEN}✅ pre-commit installed to system Python via pip.${NC}"
        elif python3 -m pip install --user pre-commit; then
            echo -e "${GREEN}✅ pre-commit installed for the current user via pip.${NC}"
            echo -e "${YELLOW}NOTE: Make sure '~/.local/bin' is in your shell's PATH.${NC}"
        elif pip3 install --user pre-commit; then
            echo -e "${GREEN}✅ pre-commit installed for the current user via pip3.${NC}"
            echo -e "${YELLOW}NOTE: Make sure '~/.local/bin' is in your shell's PATH.${NC}"
        else
            echo -e "${RED}❌ All automatic installation attempts for pre-commit failed.${NC}"
            echo -e "${RED}Please install it manually, for example:${NC} sudo /usr/bin/python3 -m pip install pre-commit"
        fi
    else
        echo -e "${RED}❌ Automatic pre-commit installation is not supported on this OS. Please install manually.${NC}"
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

# --- 6. Check and Install Git LFS ---
echo "Checking for Git LFS..."
if command -v git-lfs &> /dev/null; then
    echo -e "${GREEN}✅ Git LFS is already installed.${NC}"
else
    echo "Git LFS not found. Attempting installation..."
    if [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            $SUDO apt-get update > /dev/null && $SUDO apt-get install -y git-lfs
            echo -e "${GREEN}✅ Git LFS installed via apt.${NC}"
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            $SUDO dnf install -y git-lfs
            echo -e "${GREEN}✅ Git LFS installed via dnf.${NC}"
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            $SUDO pacman -S --noconfirm git-lfs
            echo -e "${GREEN}✅ Git LFS installed via pacman.${NC}"
        else
            echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install Git LFS manually.${NC}"
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install git-lfs
            echo -e "${GREEN}✅ Git LFS installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install Git LFS manually ('brew install git-lfs').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic Git LFS installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

# Register Git LFS filters (system-wide on Linux root; user global on macOS to avoid sudo)
if command -v git-lfs &> /dev/null; then
    if [[ "$(uname)" == "Darwin" ]]; then
        git lfs install --skip-repo &> /dev/null || true
    else
        $SUDO git lfs install --system --skip-repo &> /dev/null || git lfs install --skip-repo &> /dev/null || true
    fi
fi

echo "-------------------------------------------------"

# --- 7. Check and Install vcstool ---
echo "Checking for vcstool..."
if command -v vcs &> /dev/null; then
    echo -e "${GREEN}✅ vcstool is already installed.${NC}"
else
    echo "vcstool not found. Attempting installation..."
    if [[ "$(uname)" == "Linux" ]]; then
        installed=false
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            if $SUDO apt-get update > /dev/null && $SUDO apt-get install -y python3-vcstool; then
                echo -e "${GREEN}✅ vcstool installed via apt.${NC}"
                installed=true
            fi
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            if $SUDO dnf install -y python3-vcstool; then
                echo -e "${GREEN}✅ vcstool installed via dnf.${NC}"
                installed=true
            fi
        fi
        if [[ "$installed" == "false" ]]; then
            echo "Attempting to install with pip..."
            if $SUDO /usr/bin/python3 -m pip install $PIP_FLAGS vcstool 2>/dev/null \
               || $SUDO /usr/bin/python3 -m pip install --break-system-packages vcstool 2>/dev/null \
               || $SUDO /usr/bin/python3 -m pip install vcstool; then
                echo -e "${GREEN}✅ vcstool installed via pip.${NC}"
            else
                echo -e "${RED}❌ Could not install vcstool automatically. Please install python3-vcstool manually.${NC}"
            fi
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install vcstool
            echo -e "${GREEN}✅ vcstool installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install vcstool manually ('brew install vcstool').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic vcstool installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"

# --- 8. Check and Install cppcheck ---
echo "Checking for cppcheck..."
if command -v cppcheck &> /dev/null; then
    echo -e "${GREEN}✅ cppcheck is already installed.${NC}"
else
    echo "cppcheck not found. Attempting installation..."
    if [[ "$(uname)" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            $SUDO apt-get update > /dev/null && $SUDO apt-get install -y cppcheck
            echo -e "${GREEN}✅ cppcheck installed via apt.${NC}"
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            $SUDO dnf install -y cppcheck
            echo -e "${GREEN}✅ cppcheck installed via dnf.${NC}"
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            $SUDO pacman -S --noconfirm cppcheck
            echo -e "${GREEN}✅ cppcheck installed via pacman.${NC}"
        else
            echo -e "${RED}❌ Could not find a supported package manager (apt, dnf, pacman). Please install cppcheck manually.${NC}"
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install cppcheck
            echo -e "${GREEN}✅ cppcheck installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install cppcheck manually ('brew install cppcheck').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic cppcheck installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

# `raisin cppcheck` renders its HTML report with cppcheck-htmlreport, which some
# distributions ship in a separate package.
if command -v cppcheck &> /dev/null && ! command -v cppcheck-htmlreport &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        $SUDO apt-get install -y cppcheck-htmlreport 2>/dev/null || true
    fi
    if ! command -v cppcheck-htmlreport &> /dev/null; then
        echo -e "${YELLOW}⚠️ cppcheck-htmlreport not found. HTML cppcheck reports will be skipped.${NC}"
    fi
fi

echo "-------------------------------------------------"

# --- 9. Check and Install gcovr ---
echo "Checking for gcovr..."
if command -v gcovr &> /dev/null; then
    echo -e "${GREEN}✅ gcovr is already installed.${NC}"
else
    echo "gcovr not found. Attempting installation..."
    if [[ "$(uname)" == "Linux" ]]; then
        installed=false
        if command -v apt-get &> /dev/null; then
            echo "Attempting to install with apt..."
            if $SUDO apt-get update > /dev/null && $SUDO apt-get install -y gcovr; then
                echo -e "${GREEN}✅ gcovr installed via apt.${NC}"
                installed=true
            fi
        elif command -v dnf &> /dev/null; then
            echo "Attempting to install with dnf..."
            if $SUDO dnf install -y gcovr; then
                echo -e "${GREEN}✅ gcovr installed via dnf.${NC}"
                installed=true
            fi
        elif command -v pacman &> /dev/null; then
            echo "Attempting to install with pacman..."
            if $SUDO pacman -S --noconfirm gcovr; then
                echo -e "${GREEN}✅ gcovr installed via pacman.${NC}"
                installed=true
            fi
        fi
        if [[ "$installed" == "false" ]]; then
            echo "Attempting to install with pip..."
            if $SUDO /usr/bin/python3 -m pip install $PIP_FLAGS gcovr 2>/dev/null \
               || $SUDO /usr/bin/python3 -m pip install --break-system-packages gcovr 2>/dev/null \
               || $SUDO /usr/bin/python3 -m pip install gcovr; then
                echo -e "${GREEN}✅ gcovr installed via pip.${NC}"
            else
                echo -e "${RED}❌ Could not install gcovr automatically. Please install it manually.${NC}"
            fi
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            echo "Attempting to install with Homebrew..."
            brew install gcovr
            echo -e "${GREEN}✅ gcovr installed via Homebrew.${NC}"
        else
            echo -e "${RED}❌ Homebrew not found. Please install Homebrew first, then install gcovr manually ('brew install gcovr').${NC}"
        fi
    else
        echo -e "${RED}❌ Automatic gcovr installation is not supported on this OS. Please install manually.${NC}"
    fi
fi

echo "-------------------------------------------------"
echo -e "${GREEN}✅ System dependencies installation complete.${NC}"
