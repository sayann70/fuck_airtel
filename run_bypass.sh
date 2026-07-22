#!/usr/bin/env bash
#  run_bypass.sh  —  Airtel Hotspot Bypass  (Linux + macOS entry point)
#
#  Equivalent of RUN_AS_ADMIN.bat on Windows.
#  Self-elevates to root via sudo, then runs scripts/bypass.sh
#
#  Platforms: macOS 12+  ·  Linux (systemd / OpenRC / runit / SysV)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$EUID" -ne 0 ]]; then
    echo "  Requesting root privileges..."
    exec sudo bash "$0" "$@"
fi

exec bash "$SCRIPT_DIR/scripts/bypass.sh"
