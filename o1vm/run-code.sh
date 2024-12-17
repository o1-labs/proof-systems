#!/usr/bin/env bash
set -euo pipefail

set +u
if [ -z "${FILENAME}" ]; then
    echo "Using the latest finalized l2 block information to configure the env variables..."
    FILENAME="$(./setenv-for-latest-l2-block.sh)"
fi
set -u

source $FILENAME

if [ "${RUN_WITH_CACHED_DATA:-}" == "y" ]; then
    echo "The Op-Program and the Cannon apps were not executed because the cached data usage was requested"
else
    ./run-op-program.sh
    ./run-cannon.sh
fi

./run-vm.sh
