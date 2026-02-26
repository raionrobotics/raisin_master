#!/bin/bash
# retry-on-segfault.sh — Retry compiler invocations that segfault under QEMU
#
# QEMU user-mode emulation randomly segfaults during compilation.
# This wrapper retries the command up to 3 times on segfault.
#
# Detects segfaults via:
#   - Exit code 139 (direct SIGSEGV: 128+11)
#   - Exit code 4 (GCC ICE exit code when cc1/cc1plus crashes)

max_attempts=${RETRY_ON_SEGFAULT_ATTEMPTS:-3}

for ((attempt=1; attempt<=max_attempts; attempt++)); do
    output=$("$@" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        [ -n "$output" ] && echo "$output"
        exit 0
    fi
    # Check for segfault: direct SIGSEGV (139) or GCC ICE (4) with segfault message
    is_segfault=0
    if [ $rc -eq 139 ]; then
        is_segfault=1
    elif [ $rc -eq 4 ] && echo "$output" | grep -q "Segmentation fault"; then
        is_segfault=1
    fi
    if [ $is_segfault -eq 0 ]; then
        echo "$output" >&2
        exit $rc
    fi
    if [ $attempt -lt $max_attempts ]; then
        src_file=$(echo "$@" | grep -oP '[^ ]+\.[ch](pp|xx)?$' || true)
        echo "retry-on-segfault: segfault on attempt $attempt/$max_attempts, retrying${src_file:+: $src_file}" >&2
    else
        echo "$output" >&2
    fi
done
exit $rc
