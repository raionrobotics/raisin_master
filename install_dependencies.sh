#!/usr/bin/env bash
# install_dependencies.sh
# -----------------------
# Purpose  : Run package-specific dependency installers directly from source locations.
# Sources  : - src/<pkg>/install_dependencies.sh
#            - release/install/<pkg>/<os>/<os_version>/<arch>/<build_type>/install_dependencies.sh
# Usage    : sudo bash install_dependencies.sh
# Note     : Run `raisin setup` first to download release packages.

set -euo pipefail

# Absolute path to the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prevent globbing patterns from expanding to themselves when no match is found
shopt -s nullglob

# --- Detect system info ---
detect_os_type() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *)       echo "unknown" ;;
    esac
}

detect_os_version() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        local id="${ID:-unknown}"
        local version="${VERSION_ID:-}"
        if [[ -n "${version}" ]]; then
            echo "${id}${version}"
        else
            echo "${id}"
        fi
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        echo "macos$(sw_vers -productVersion | cut -d. -f1,2)"
    else
        echo "unknown"
    fi
}

detect_architecture() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *)            echo "${arch}" ;;
    esac
}

OS_TYPE="$(detect_os_type)"
OS_VERSION="$(detect_os_version)"
ARCH="$(detect_architecture)"

# --- Setup ---
# Color codes for beautiful output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running package-specific dependency installers...${NC}"
echo -e "${BLUE}System: ${OS_TYPE}/${OS_VERSION}/${ARCH}${NC}"
echo "================================================================="
echo ""

# Track which installers we found and their results
found_installers=0
failed_installers=()
# Track processed packages to avoid duplicates
declare -A processed_packages

# Function to run an installer script
run_installer() {
    local installer="$1"
    local pkg_name="$2"
    local source_type="$3"

    echo -e "${YELLOW}🔧 Running installer for: ${pkg_name} (${source_type})${NC}"

    if [[ -x "${installer}" ]]; then
        # Script is executable, run it directly
        if "${installer}"; then
            echo -e "${GREEN}   ✅ Completed: ${pkg_name}${NC}"
            return 0
        else
            echo -e "${RED}   ❌ Failed: ${pkg_name}${NC}"
            return 1
        fi
    else
        # Script is not executable, run via bash
        if bash "${installer}"; then
            echo -e "${GREEN}   ✅ Completed: ${pkg_name}${NC}"
            return 0
        else
            echo -e "${RED}   ❌ Failed: ${pkg_name}${NC}"
            return 1
        fi
    fi
}

# --- Run installers from src/<pkg>/install_dependencies.sh ---
if [[ -d "${SCRIPT_DIR}/src" ]]; then
    echo -e "${BLUE}📂 Checking source packages (src/)...${NC}"
    for pkg_dir in "${SCRIPT_DIR}"/src/*/; do
        if [[ -d "${pkg_dir}" ]]; then
            installer="${pkg_dir}install_dependencies.sh"
            if [[ -f "${installer}" ]]; then
                pkg_name="$(basename "${pkg_dir}")"
                processed_packages["${pkg_name}"]=1
                ((found_installers++))
                if ! run_installer "${installer}" "${pkg_name}" "src"; then
                    failed_installers+=("${pkg_name}")
                fi
                echo ""
            fi
        fi
    done
fi

# --- Run installers from release/install/<pkg>/<os>/<os_version>/<arch>/<build_type>/install_dependencies.sh ---
release_install_dir="${SCRIPT_DIR}/release/install"
if [[ -d "${release_install_dir}" ]]; then
    echo -e "${BLUE}📂 Checking release packages (release/install/)...${NC}"
    for pkg_dir in "${release_install_dir}"/*/; do
        if [[ -d "${pkg_dir}" ]]; then
            pkg_name="$(basename "${pkg_dir}")"

            # Skip if already processed from src/
            if [[ -n "${processed_packages[${pkg_name}]:-}" ]]; then
                echo -e "${YELLOW}   ⏭️  Skipping ${pkg_name} (already installed from src/)${NC}"
                continue
            fi

            # Look for installer in matching OS/version/arch path
            # Check all build types (release, debug, etc.)
            for build_type_dir in "${pkg_dir}${OS_TYPE}/${OS_VERSION}/${ARCH}"/*/; do
                if [[ -d "${build_type_dir}" ]]; then
                    installer="${build_type_dir}install_dependencies.sh"
                    if [[ -f "${installer}" ]]; then
                        # Only run once per package (first build_type found)
                        if [[ -z "${processed_packages[${pkg_name}]:-}" ]]; then
                            processed_packages["${pkg_name}"]=1
                            ((found_installers++))
                            build_type="$(basename "${build_type_dir}")"
                            if ! run_installer "${installer}" "${pkg_name}" "release/${build_type}"; then
                                failed_installers+=("${pkg_name}")
                            fi
                            echo ""
                        fi
                    fi
                fi
            done
        fi
    done
fi

# --- Summary ---
echo "================================================================="
if [[ ${found_installers} -eq 0 ]]; then
    echo -e "${YELLOW}📦 No package dependency installers found.${NC}"
    echo ""
    echo "To install package dependencies:"
    echo "  1. Clone source packages to src/ and/or run 'raisin install <pkg>'"
    echo "  2. Run 'sudo bash install_dependencies.sh' again"
else
    if [[ ${#failed_installers[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ All ${found_installers} package installer(s) completed successfully.${NC}"
    else
        echo -e "${YELLOW}⚠️  ${found_installers} installer(s) found, ${#failed_installers[@]} failed:${NC}"
        for failed in "${failed_installers[@]}"; do
            echo -e "${RED}   - ${failed}${NC}"
        done
        echo ""
        echo "You may need to run the failed installers manually or check their output."
    fi
fi
echo ""
