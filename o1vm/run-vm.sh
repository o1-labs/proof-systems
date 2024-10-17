#!/usr/bin/env bash
set -euo pipefail

O1VM_FLAVOR="${O1VM_FLAVOR:-pickles}"

case ${O1VM_FLAVOR} in
"legacy")
    BINARY_FLAVOR="legacy_o1vm"
    ;;
"pickles")
    BINARY_FLAVOR="pickles_o1vm"
    ;;
*)
    echo "${BASH_SOURCE[0]}:${LINENO}: only flavors 'legacy' and \
'pickles' (default) are supported for now. Use the environment variable \
O1VM_FLAVOR to one of these values to run the flavor you would like"
    exit 1
    ;;
esac

if [ -f "snapshot-state-10000000.json" ]; then
    ZKVM_STATE_FILENAME="./snapshot-state-10000000.json"
fi

cargo run --bin ${BINARY_FLAVOR} \
    --all-features \
    --release \
    -p o1vm -- \
    --pprof.cpu \
    --info-at "${INFO_AT:-%10000000}" \
    --snapshot-state-at "${SNAPSHOT_STATE_AT:-%10000000}" \
    --proof-at never \
    --stop-at "${STOP_AT:-never}" \
    --input "${ZKVM_STATE_FILENAME:-./state.json}" \
    --preimage-oracle "${PREIMAGE_ORACLE_IMPLEMENTATION:-network}" \
    -- \
    ./ethereum-optimism/op-program/bin/op-program \
    --log.level DEBUG \
    --l1 "${L1_RPC}" \
    --l2 "${L2_RPC}" \
    --network sepolia \
    --datadir "${OP_PROGRAM_DATA_DIR}" \
    --l1.head "${L1_HEAD}" \
    --l2.head "${L2_HEAD}" \
    --l2.outputroot "${STARTING_OUTPUT_ROOT}" \
    --l2.claim "${L2_CLAIM}" \
    --l2.blocknumber "${L2_BLOCK_NUMBER}" \
    --server
