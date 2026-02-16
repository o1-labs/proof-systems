#!/usr/bin/env bash
set -euo pipefail

START=$(date +%s)

echo ""
echo "Cleaning up the E2E testing cache file system..."
echo ""
rm -rf op-program-db-for-latest-l2-block \
  env-for-latest-l2-block.sh \
  snapshot-state-3000000.json \
  state.json \
  meta.json \
  out.json \
  cpu.pprof

RUNTIME=$(($(date +%s) - START))
echo ""
echo "Execution time: ${RUNTIME} s"
echo ""
