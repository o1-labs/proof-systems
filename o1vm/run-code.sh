#!/usr/bin/env bash
set -euo pipefail

set +u
if [ -z "${FILENAME}" ]; then
    echo "Using the latest block information to configure the env variables..."
    FILENAME="$(./setenv-for-latest-block.sh)"
fi
set -u

source $FILENAME

./run-op-program.sh
./run-cannon.sh
./run-vm.sh
