#!/usr/bin/env bash
# install_system_deps.sh
# ----------------------
# Purpose  : Install raisin_master's build tools: the apt packages declared in deps/apt.build.txt and
#            deps/apt.build.ubuntu-<version>.txt (format: deps/README.md) that are not installed yet.
#            pre-commit and the documentation tools are not installed here: they are pinned in
#            requirements.txt and installed into the RAISIN virtual environment.
# Usage    : Called by `./raisin --install` or run manually. Arguments are ignored (raion-setup passes -y).
# Platform : Ubuntu (apt) only. On other systems install the listed tools yourself or use the dev container.
#            The raisin-base build image already holds every tool, so in its containers apt is not called.

set -euo pipefail

# root installs directly (a minimal container may have no sudo); everyone else goes through sudo,
# as the packages' install_dependencies.sh does.
SUDO=""
if [[ ${EUID} -ne 0 ]]; then
    SUDO="sudo"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: apt-get not found. Install the tools in ${SCRIPT_DIR}/deps/apt.build.txt yourself, or use the dev container." >&2
    exit 1
fi

# Read Ubuntu version from /etc/os-release (lsb_release is absent on minimal installs)
ubuntu_version="$(. /etc/os-release && echo "${VERSION_ID:-}")"

names=()
for list in "${SCRIPT_DIR}/deps/apt.build.txt" "${SCRIPT_DIR}/deps/apt.build.ubuntu-${ubuntu_version}.txt"; do
    [[ -f "${list}" ]] || continue
    # read -ra splits on whitespace without expanding globs; awk drops comments.
    while read -ra words; do
        names+=("${words[@]}")
    done < <(awk '{ sub(/#.*/, ""); print }' "${list}")
done

missing=()
for pkg in "${names[@]}"; do
    if [[ "$(dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null)" != "install ok installed" ]]; then
        missing+=("${pkg}")
    fi
done

if [[ ${#missing[@]} -eq 0 ]]; then
    echo "✅ Build tools (deps/apt.build.txt) are already installed."
else
    echo "📦 Installing build tools (deps/apt.build.txt): ${missing[*]}"
    # A broken source (removed repository, expired key) fails the update for that source only;
    # apt install below decides whether the tools can be installed.
    if ! ${SUDO} apt-get update; then
        echo "WARNING: apt-get update reported errors (see above). Continuing with the package lists apt has." >&2
    fi
    # apt runs package scripts on a pseudo-terminal, so a debconf question (tzdata asks for the time zone)
    # waits for an answer even without a user, as in CI. noninteractive takes the defaults (tzdata: UTC).
    # Passed through env because sudo drops the caller's environment.
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
fi

# vcstool provides `vcs`, which src/setup.sh imports the repositories with. On 24.04 it comes from
# apt (deps/apt.build.ubuntu-24.04.txt) above. Workaround for 22.04 only, whose archive does not have
# it: install it into the system Python with pip, unpinned (src/setup.sh runs outside the virtual
# environment). Remove this block when 22.04 support ends. 22.04's pip does not know
# --break-system-packages, hence the second try.
if command -v vcs >/dev/null 2>&1; then
    echo "✅ vcstool is already installed."
else
    echo "📦 Installing vcstool..."
    ${SUDO} python3 -m pip install --break-system-packages vcstool 2>/dev/null \
        || ${SUDO} python3 -m pip install vcstool
fi
