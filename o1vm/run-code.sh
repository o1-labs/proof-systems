#!/usr/bin/env bash
set -euo pipefail

set +u
if [ -z "${FILENAME}" ]; then
    echo "Using the latest finalized l2 block information to configure the env variables..."
    FILENAME="$(./setenv-for-latest-l2-block.sh)"
fi
set -u

source $FILENAME

if [ -d "op-program-db-for-latest-l2-block" ] && [ -f "env-for-latest-l2-block.sh" ] && [ -f "snapshot-state-3000000.json" ] && [ -f "meta.json" ]; then
    echo "The Op-Program and the Cannon apps were not executed because of the cache data presence"
else
    ./run-op-program.sh
    ./run-cannon.sh
fi
./run-vm.sh
