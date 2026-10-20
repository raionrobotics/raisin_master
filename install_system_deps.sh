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

# Every declared name, with the file that declares it.
names=()
sources=()
for list in "${SCRIPT_DIR}/deps/apt.build.txt" "${SCRIPT_DIR}/deps/apt.build.ubuntu-${ubuntu_version}.txt"; do
    [[ -f "${list}" ]] || continue
    # read -ra splits on whitespace without expanding globs; awk drops comments.
    while read -ra words; do
        for pkg in "${words[@]}"; do
            names+=("${pkg}")
            sources+=("${list}")
        done
    done < <(awk '{ sub(/#.*/, ""); print }' "${list}")
done

# The ones not installed yet, with their files.
to_install=()
to_install_sources=()
for i in "${!names[@]}"; do
    if [[ "$(dpkg-query -W -f='${Status}' "${names[$i]}" 2>/dev/null)" != "install ok installed" ]]; then
        to_install+=("${names[$i]}")
        to_install_sources+=("${sources[$i]}")
    fi
done

if [[ ${#names[@]} -eq 0 ]]; then
    echo "No apt packages declared in ${SCRIPT_DIR}/deps/ (apt.build*.txt); nothing to install."
elif [[ ${#to_install[@]} -eq 0 ]]; then
    echo "✅ Build tools (deps/apt.build.txt) are already installed."
else
    echo "📦 Installing build tools (deps/apt.build.txt): ${to_install[*]}"
    # A broken source (removed repository, expired key) fails the update for that source only;
    # the name check and apt install below decide whether the tools can be installed.
    if ! ${SUDO} apt-get update; then
        echo "WARNING: apt-get update reported errors (see above). Continuing with the package lists apt has." >&2
    fi

    # Every name to install must exist in this system's archive; installed ones already do. The same
    # check as the packages' install_dependencies.sh: one apt-cache call prints a "name:" block with a
    # "Candidate:" line for every name it knows and nothing for an unknown one, and a virtual name's
    # candidate is "(none)"; both count as unavailable. LC_ALL=C keeps the label from being translated.
    # Captured with $( ) so that a failing apt-cache stops the script under set -e.
    declare -A available=()
    policy=$(LC_ALL=C apt-cache policy "${to_install[@]}")
    while read -r pkg; do
        available[$pkg]=1
    done < <(awk '/^[^ ].*:$/ { name = substr($0, 1, length($0) - 1) }
                  /^  Candidate:/ && $2 != "(none)" { print name }' <<< "${policy}")
    unavailable=()
    for i in "${!to_install[@]}"; do
        if [[ -z "${available[${to_install[$i]}]:-}" ]]; then
            unavailable+=("${to_install[$i]}  (${to_install_sources[$i]})")
        fi
    done
    if [[ ${#unavailable[@]} -gt 0 ]]; then
        echo "ERROR: ${#unavailable[@]} declared apt package(s) are not available on Ubuntu ${ubuntu_version} ($(dpkg --print-architecture)):" >&2
        printf '  %s\n' "${unavailable[@]}" >&2
        echo "Nothing was installed. Fix or move these names in the listed files." >&2
        exit 1
    fi

    # apt runs package scripts on a pseudo-terminal, so a debconf question (tzdata asks for the time zone)
    # waits for an answer even without a user, as in CI. noninteractive takes the defaults (tzdata: UTC).
    # Passed through env because sudo drops the caller's environment.
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
fi
