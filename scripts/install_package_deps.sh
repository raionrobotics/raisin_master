#!/usr/bin/env bash
# install_package_deps.sh
# -----------------------
# Purpose  : Install what one package declares in its deps/ (format: deps/README.md): the apt packages
#            in deps/apt*.txt and the udev rules in deps/udev/.
# Usage    : bash scripts/install_package_deps.sh <package directory>
#            Without an argument it installs the deps/ next to itself: `raisin publish` copies this file
#            into each package's install tree as install_dependencies.sh, which robots run from there.
# Callers  : the workspace root install_dependencies.sh, for a package in src/ without its own script.

set -euo pipefail

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# Read Ubuntu version from /etc/os-release (lsb_release is absent on minimal installs)
UBUNTU_VERSION=$(. /etc/os-release && echo "${VERSION_ID:-}")

PKG_DIR="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")}" && pwd)"

# Update and install dependencies
echo "Installing system dependencies..."

# Every declared package must exist in this system's archive. A missing one is not skipped:
# all of them are listed with the file that declares them, and the script fails before
# installing anything, so the name is fixed in deps/.
# Every declared name, with the file that declares it. read -ra splits a line on whitespace
# without expanding globs. A package name has no whitespace, so the split is unambiguous.
# awk strips comments and ends every line with a newline, so read keeps a last line that has none.
names=()
sources=()
for list in "$PKG_DIR/deps/apt.txt" "$PKG_DIR/deps/apt.ubuntu-${UBUNTU_VERSION}.txt" \
            "$PKG_DIR/deps/apt.build.txt" "$PKG_DIR/deps/apt.build.ubuntu-${UBUNTU_VERSION}.txt"; do
    [ -f "$list" ] || continue
    while read -ra words; do
        for pkg in "${words[@]}"; do
            names+=( "$pkg" )
            sources+=( "$list" )
        done
    done < <(awk '{ sub(/#.*/, ""); print }' "$list")
done

# One apt-cache call for every name: each call reads the whole package cache, and 61 names
# looked up one at a time took 24-30 s. apt-cache prints a "name:" block with a "Candidate:"
# line for every name it knows and nothing for an unknown one; a virtual name's candidate is
# "(none)". Both count as missing. LC_ALL=C keeps the "Candidate:" label from being translated.
# Called only with names: without arguments apt-cache policy prints the repository priorities.
# Captured with $( ) rather than read from < <( ): a failing apt-cache (a malformed sources entry
# exits 100) then stops the script under set -e, instead of reporting every name as missing.
declare -A available=()
if [ ${#names[@]} -gt 0 ]; then
    echo "Updating package list..."
    # Only when something is declared: a package that declares nothing needs no package lists.
    # A broken source (removed repository, expired key) fails the update for that source only;
    # the rest are refreshed. Stopping here would skip every package, so warn and let the name
    # check and apt install below decide.
    if ! $SUDO apt update; then
        echo "WARNING: apt update reported errors (see above). Continuing with the package lists apt has; a package that cannot be installed fails below." >&2
    fi
    policy=$(LC_ALL=C apt-cache policy "${names[@]}")
    while read -r pkg; do
        available[$pkg]=1
    done < <(awk '/^[^ ].*:$/ { name = substr($0, 1, length($0) - 1) }
                  /^  Candidate:/ && $2 != "(none)" { print name }' <<< "$policy")
fi

packages=()
missing=()
for i in "${!names[@]}"; do
    if [ -n "${available[${names[$i]}]:-}" ]; then
        packages+=( "${names[$i]}" )
    else
        missing+=( "${names[$i]}  (${sources[$i]})" )
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: ${#missing[@]} declared apt package(s) are not available on Ubuntu ${UBUNTU_VERSION} ($(dpkg --print-architecture)):" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo "Nothing was installed. Fix or move these names in the listed files." >&2
    exit 1
fi

if [ ${#packages[@]} -eq 0 ]; then
    # A package that needs nothing from apt has no deps/apt*.txt, or only comments in them.
    echo "No apt packages declared in $PKG_DIR/deps/ (apt*.txt); nothing to install."
else
    echo "Installing dependencies: ${packages[*]}"
    # apt-get runs package scripts on a pseudo-terminal, so a debconf question (tzdata asks for the time zone)
    # waits for an answer even without a user, as on the robot service or in CI. noninteractive takes the
    # defaults (tzdata: UTC). Passed through env because sudo drops the caller's environment.
    $SUDO env DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}"
fi

# udev rules give a device's permissions to the users who run the package without root.
# They are host settings: a container has no udev daemon (no /run/udev/control), and its /etc
# would not reach the host anyway, so there they are reported and skipped.
rules=()
for rule in "$PKG_DIR"/deps/udev/*.rules; do
    if [ -f "$rule" ]; then
        rules+=( "$rule" )
    fi
done
if [ ${#rules[@]} -gt 0 ]; then
    if [ -S /run/udev/control ]; then
        # A rule is copied only when it is new or differs, and udev re-reads its rules only then:
        # the trigger re-applies the rules to every USB device, which an unchanged rule does not need.
        changed=0
        for rule in "${rules[@]}"; do
            target="/etc/udev/rules.d/$(basename "$rule")"
            if ! cmp -s "$rule" "$target"; then
                $SUDO install -m 0644 "$rule" "$target"
                echo "Installed udev rule: $target"
                changed=1
            fi
        done
        if [ $changed -eq 1 ]; then
            $SUDO udevadm control --reload-rules
            $SUDO udevadm trigger --subsystem-match=usb
        fi
    else
        echo "udev is not running here (no /run/udev/control); skipped ${#rules[@]} udev rule(s) in $PKG_DIR/deps/udev/."
    fi
fi

echo "All dependencies installed successfully!"
exit 0
