#!/bin/bash
# g++ wrapper with QEMU segfault retry
exec "$(dirname "$0")/retry-on-segfault.sh" g++ "$@"
