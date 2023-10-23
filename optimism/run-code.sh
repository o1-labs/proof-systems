#!/usr/bin/env bash
set -euo pipefail

source rpcs.sh

FILENAME="$(./generate-config.sh)"

source $FILENAME

./run-op-program.sh
