#!/usr/bin/env bash
#
# The profiler used is https://github.com/mstange/samply
# Do `cargo install samply` before using this script
#
# The script is assumed to be launched from within this directory.

set -euo pipefail

source rpcs.sh

# Fix some default data to profile against. 
# It probably does not matter much.
source ${DATAFILE:-2023-12-19-10-10-12-op-program-data-log.sh}

set -x

cargo build --release --bin kimchi_optimism

 ~/.cargo/bin/samply record \
                     -o ./op.profile.json -d 100 -- \
                     $(pwd)/../target/release/kimchi_optimism \
    --pprof.cpu \
    --info-at 'never' \
    --proof-at never \
    --stop-at '=1000000000' \
    --input "${ZKVM_STATE_FILENAME:-./state.json}" \
    -- \
    ./ethereum-optimism/op-program/bin/op-program \
    --log.level DEBUG \
    --l1 "${L1RPC}" \
    --l2 "${L2RPC}" \
    --network sepolia \
    --datadir "${OP_PROGRAM_DATA_DIR}" \
    --l1.head "${L1_HEAD}" \
    --l2.head "${L2_HEAD}" \
    --l2.outputroot "${STARTING_OUTPUT_ROOT}" \
    --l2.claim "${L2_CLAIM}" \
    --l2.blocknumber "${L2_BLOCK_NUMBER}" \
    --server
