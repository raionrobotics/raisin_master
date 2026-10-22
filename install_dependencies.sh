#!/usr/bin/env bash
# install_dependencies.sh
# -----------------------
# Purpose  : Run package-specific dependency installers directly from source locations.
# Sources  : - src/<pkg>/install_dependencies.sh
#            - release/install/<pkg>/<os>/<os_version>/<arch>/<build_type>/install_dependencies.sh
# Usage    : sudo bash install_dependencies.sh
# Delivered-only: sudo bash install_dependencies.sh --delivered-build-type=release
# Detached runner: add --delivered-workspace=/absolute/canonical/workspace
# Note     : Run `raisin setup` first to download release packages.

set -euo pipefail

# Selection only, not archive authentication or a worker-completion receipt.
selection_error() {
    echo "Invalid delivered dependency selection" >&2
    exit 2
}

valid_build_type() {
    local LC_ALL=C value="$1"
    [[ ${#value} -le 64 && "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

DELIVERED_BUILD_TYPE=""
DELIVERED_WORKSPACE=""
unexpected_argument=false
for argument in "$@"; do
    case "$argument" in
        --delivered-build-type=*)
            [[ -z "$DELIVERED_BUILD_TYPE" ]] || selection_error
            value="${argument#--delivered-build-type=}"
            valid_build_type "$value" || selection_error
            DELIVERED_BUILD_TYPE="$value"
            ;;
        --delivered-build-type*) selection_error ;;
        --delivered-workspace=*)
            [[ -z "$DELIVERED_WORKSPACE" ]] || selection_error
            value="${argument#--delivered-workspace=}"
            [[ -n "$value" ]] || selection_error
            DELIVERED_WORKSPACE="$value"
            ;;
        --delivered-workspace*) selection_error ;;
        -y) ;;  # Already accepted by provisioning; not forwarded to packages.
        *) unexpected_argument=true ;;  # Preserve ignored legacy arguments.
    esac
done
if [[ -n "$DELIVERED_BUILD_TYPE" && "$unexpected_argument" == true ]]; then
    selection_error
fi

# An independently bound worker may execute pinned bytes outside the workspace.
# This path selector is not authorization to perform root work in that location.
if [[ -n "$DELIVERED_WORKSPACE" ]]; then
    [[ -n "$DELIVERED_BUILD_TYPE" ]] || selection_error
    valid_workspace() {
        local LC_ALL=C value="$1"
        local -a components
        [[ ${#value} -ge 2 && ${#value} -le 2048 &&
           "$value" =~ ^/[A-Za-z0-9_./-]+$ ]] || return 1
        case "$value" in *//*|*/|*/./*|*/../*|*/.|*/..) return 1 ;; esac
        IFS=/ read -r -a components <<< "$value"
        [[ ${#components[@]} -le 64 ]]
    }
    valid_workspace "$DELIVERED_WORKSPACE" || selection_error
    SCRIPT_DIR="$(cd -P -- "$DELIVERED_WORKSPACE" 2>/dev/null && pwd -P)" || selection_error
    [[ "$SCRIPT_DIR" == "$DELIVERED_WORKSPACE" ]] || selection_error
else
    # Preserve the developer/source runner's existing script-relative behavior.
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [[ -n "$DELIVERED_BUILD_TYPE" && ! -d "$SCRIPT_DIR/release/install" ]]; then
    selection_error
fi

# Prevent globbing patterns from expanding to themselves when no match is found
shopt -s nullglob

# --- Detect system info ---
# These functions match the logic in commands/utils.py get_os_info()
detect_os_type() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "${ID:-linux}"
    else
        case "$(uname -s)" in
            Linux*)  echo "linux" ;;
            Darwin*) echo "macos" ;;
            CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
            *)       echo "unknown" ;;
        esac
    fi
}

detect_os_version() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "${VERSION_ID:-unknown}"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        # Match Python's platform.mac_ver() format
        sw_vers -productVersion
    else
        echo "unknown"
    fi
}

detect_architecture() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "arm64" ;;
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
if [[ -z "$DELIVERED_BUILD_TYPE" && -d "${SCRIPT_DIR}/src" ]]; then
    echo -e "${BLUE}📂 Checking source packages (src/)...${NC}"
    for pkg_dir in "${SCRIPT_DIR}"/src/*/; do
        if [[ -d "${pkg_dir}" ]]; then
            installer="${pkg_dir}install_dependencies.sh"
            if [[ -f "${installer}" ]]; then
                pkg_name="$(basename "${pkg_dir}")"
                processed_packages["${pkg_name}"]=1
                ((found_installers++)) || true
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

            # Explicit mode never falls back to another build type.
            if [[ -n "$DELIVERED_BUILD_TYPE" ]]; then
                build_type_dirs=("${pkg_dir}${OS_TYPE}/${OS_VERSION}/${ARCH}/${DELIVERED_BUILD_TYPE}/")
            else
                build_type_dirs=("${pkg_dir}${OS_TYPE}/${OS_VERSION}/${ARCH}"/*/)
            fi
            for build_type_dir in "${build_type_dirs[@]}"; do
                if [[ -d "${build_type_dir}" ]]; then
                    installer="${build_type_dir}install_dependencies.sh"
                    if [[ -f "${installer}" ]]; then
                        # Only run once per package (first build_type found)
                        if [[ -z "${processed_packages[${pkg_name}]:-}" ]]; then
                            processed_packages["${pkg_name}"]=1
                            ((found_installers++)) || true
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
        echo -e "${RED}❌ ${found_installers} installer(s) found, ${#failed_installers[@]} failed:${NC}"
        for failed in "${failed_installers[@]}"; do
            echo -e "${RED}   - ${failed}${NC}"
        done
        echo ""
        echo "Each failed installer printed its reason above (e.g. the apt packages it could not find)."
        echo ""
        exit 1
    fi
fi
echo ""
