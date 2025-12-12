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

# Iterate over each *direct* sub-directory
for subdir in "$SCRIPT_DIR/dependencies"/*/; do
  installer="${subdir}install_dependencies.sh"

  # If the installer script exists, run it
  if [[ -f "$installer" ]]; then
    echo "▶️  [$subdir] Found install_dependencies.sh"

    # Execute directly if it has the executable bit, otherwise via bash
    if [[ -x "$installer" ]]; then
      "$installer"
    else
      bash "$installer"
    fi
  fi
done
