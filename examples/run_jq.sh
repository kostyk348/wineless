#!/usr/bin/env bash
# Run the OFFICIAL Windows jq.exe (MSVC build) on Linux, without Wine.
set -euo pipefail
[ -f jq.exe ] || curl -sL -o jq.exe \
  https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe
wineless run jq.exe -- --version
