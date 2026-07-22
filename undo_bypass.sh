#!/usr/bin/env bash
#  undo_bypass.sh  —  Revert Airtel Bypass  (Linux + macOS entry point)
#
#  Equivalent of UNDO_BYPASS.bat on Windows.
#  Self-elevates to root via sudo, then runs bypass.sh --undo
#
#  Platforms: macOS 12+  ·  Linux (systemd / OpenRC / runit / SysV)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$EUID" -ne 0 ]]; then
    echo "  Requesting root privileges..."
    exec sudo bash "$0" "$@"
fi

exec bash "$SCRIPT_DIR/scripts/bypass.sh" --undo
