#!/usr/bin/env bash
set -euo pipefail

set +u
if [ -z "${FILENAME}" ]; then
    echo "Using the latest finalized l2 block information to configure the env variables..."
    FILENAME="$(./setenv-for-latest-l2-block.sh)"
fi
set -u

source $FILENAME

#./run-op-program.sh
./run-cannon.sh
#./run-vm.sh
