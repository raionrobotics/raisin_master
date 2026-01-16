#!/usr/bin/env bash
# install_dependencies.sh
# -----------------------
# Purpose  : Run package-specific dependency installers.
# Source   : install/dependencies/<pkg>/install_dependencies.sh
# Usage    : sudo bash install_dependencies.sh
# Note     : Run `raisin setup` first to copy install scripts to install/dependencies/.
#            - Source packages (src/) are copied by copy_installers()
#            - Release packages are copied by deploy_install_packages()

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

echo -e "${YELLOW}Running package-specific dependency installers...${NC}"
echo "================================================================="
echo ""

# Track which installers we found and their results
found_installers=0
failed_installers=()

# Function to run an installer script
run_installer() {
    local installer="$1"
    local pkg_name="$2"

    echo -e "${YELLOW}🔧 Running installer for: ${pkg_name}${NC}"

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

# --- Run installers from install/dependencies/<pkg>/install_dependencies.sh ---
# All installers are copied here by 'raisin setup':
#   - Source packages: copied by copy_installers()
#   - Release packages: copied by deploy_install_packages()
if [[ -d "${SCRIPT_DIR}/install/dependencies" ]]; then
    for pkg_dir in "${SCRIPT_DIR}"/install/dependencies/*/; do
        if [[ -d "${pkg_dir}" ]]; then
            installer="${pkg_dir}install_dependencies.sh"
            if [[ -f "${installer}" ]]; then
                pkg_name="$(basename "${pkg_dir}")"
                ((found_installers++))
                if ! run_installer "${installer}" "${pkg_name}"; then
                    failed_installers+=("${pkg_name}")
                fi
                echo ""
            fi
        fi
    done
fi

# --- Summary ---
echo "================================================================="
if [[ ${found_installers} -eq 0 ]]; then
    echo -e "${YELLOW}📦 No package dependency installers found in install/dependencies/.${NC}"
    echo ""
    echo "To install package dependencies:"
    echo "  1. Clone source packages to src/ and/or run 'raisin install <pkg>'"
    echo "  2. Run 'raisin setup' to copy install scripts to install/dependencies/"
    echo "  3. Run 'sudo bash install_dependencies.sh' again"
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
