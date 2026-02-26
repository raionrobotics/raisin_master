#!/bin/bash
# retry-on-segfault.sh — Retry compiler invocations that segfault under QEMU
# Used as CMAKE_C_COMPILER_LAUNCHER / CMAKE_CXX_COMPILER_LAUNCHER
#
# QEMU user-mode emulation randomly segfaults during compilation.
# This wrapper retries the command up to 3 times on SIGSEGV (exit code 139).

max_attempts=${RETRY_ON_SEGFAULT_ATTEMPTS:-3}

for ((attempt=1; attempt<=max_attempts; attempt++)); do
    "$@"
    rc=$?
    [ $rc -eq 0 ] && exit 0
    # SIGSEGV: signal 11 → exit code 128+11=139
    if [ $rc -ne 139 ]; then
        exit $rc
    fi
    if [ $attempt -lt $max_attempts ]; then
        echo "retry-on-segfault: SIGSEGV on attempt $attempt/$max_attempts, retrying: $(basename "$1") ...$(echo "$@" | grep -oP '\S+\.[ch](pp|xx)?$')" >&2
    fi
done
exit $rc
