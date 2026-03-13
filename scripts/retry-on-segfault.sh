#!/bin/bash
# retry-on-segfault.sh — Retry compiler/linker invocations that segfault under QEMU
#
# QEMU user-mode emulation randomly segfaults during compilation.
# This wrapper retries the command up to 3 times on segfault.
#
# Exit codes that trigger retry:
#   139 = direct SIGSEGV (128+11)
#   4   = GCC ICE (cc1/cc1plus crashed internally)

max_attempts=${RETRY_ON_SEGFAULT_ATTEMPTS:-3}

for ((attempt=1; attempt<=max_attempts; attempt++)); do
    "$@"
    rc=$?
    [ $rc -eq 0 ] && exit 0
    # Only retry on segfault (139) or GCC internal error (4)
    if [ $rc -ne 139 ] && [ $rc -ne 4 ]; then
        exit $rc
    fi
    if [ $attempt -lt $max_attempts ]; then
        echo "retry-on-segfault: exit code $rc on attempt $attempt/$max_attempts, retrying..." >&2
    fi
done
exit $rc
