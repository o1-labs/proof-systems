#!/usr/bin/env bash
set -euo pipefail

START=$(date +%s)

echo ""
echo "Fetching the E2E testing cache..."
echo ""
docker run --rm -it --name o1vm-e2e-testing-cache --pull=always -v ./:/tmp/cache o1labs/proof-systems:o1vm-e2e-testing-cache
unzip -q -o o1vm-e2e-testing-cache.zip -d ./
rm -rf o1vm-e2e-testing-cache.zip

RUNTIME=$(($(date +%s) - START))
echo ""
echo "Execution time: ${RUNTIME} s"
echo ""
