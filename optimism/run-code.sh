#!/usr/bin/env bash
set -euo pipefail

source rpcs.sh

set +u
if [ -z "${FILENAME}" ]; then
    FILENAME="$(./generate-config.sh)"
fi
set -u

source $FILENAME

#./run-op-program.sh

./run-vm.sh
