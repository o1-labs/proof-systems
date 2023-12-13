#!/usr/bin/env bash
set -euo pipefail

cargo run --bin kimchi_optimism --release -p kimchi_optimism -- \
    --pprof-cpu \
    --info-at "${INFO_AT:-%10000000}" \
    --proof-at never \
    --stop-at "${STOP_AT:-never}" \
    --input "${STATE_FILENAME:-./state.json}" \
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
