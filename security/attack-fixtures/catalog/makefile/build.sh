#!/usr/bin/env sh
# INERT test fixture: shell script executing build step targeting canary path
TARGET="${CANARY_PATH:-{{CANARY_PATH}}}"
if [ -n "$TARGET" ]; then
    echo "CANARY_TOUCHED_BY_MAKEFILE" > "$TARGET" 2>/dev/null || true
fi
