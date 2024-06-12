#!/usr/bin/env bash
set -euo pipefail

source rpcs.sh

# AnchorStateRegistry (or ASR) on L1 Sepolia
ANCHOR_STATE_REGISTRY=0x218CD9489199F321E1177b56385d333c5B598629

# ASR returns the output root and the L2 Block Number of the latest finalized
# output root.
ANCHOR_OUTPUT=$(cast call  --rpc-url "${L1_RPC}" ${ANCHOR_STATE_REGISTRY} 'anchors(uint32) returns(bytes32,uint256)' 0)
L2_CLAIM=$(echo ${ANCHOR_OUTPUT} | cut -d' ' -f 1)
L2_BLOCK_NUMBER=$(echo ${ANCHOR_OUTPUT} | cut -d' ' -f 2)

OUTPUT_L2_PREVIOUS_BLOCK=$(cast rpc optimism_outputAtBlock $(cast th $((L2_BLOCK_NUMBER-1))) --rpc-url "${OP_NODE_RPC}")
# We use the STARTING_OUTPUT_ROOT as the output state just prior to the
# L2_BLOCK_NUMBER
STARTING_OUTPUT_ROOT=$(echo $OUTPUT_L2_PREVIOUS_BLOCK | jq -r .outputRoot)
L2_HEAD=$(echo $OUTPUT_L2_PREVIOUS_BLOCK | jq -r .blockRef.hash)

L1_FINALIZED_NUMBER=$(cast block finalized --rpc-url "${L1_RPC}" -f number)
L1_FINALIZED_HASH=$(cast block "${L1_FINALIZED_NUMBER}" --rpc-url "${L1_RPC}" -f hash)
L1_HEAD=$L1_FINALIZED_HASH

echo "The claim of the transition to block ${L2_BLOCK_NUMBER} is $L2_CLAIM" 1>&2

FILENAME=env-for-latest-l2-block.sh

# Delete all lines in the file if it already exists
cat /dev/null > ${FILENAME}

OP_PROGRAM_DATA_DIR=$(pwd)/op-program-db-for-latest-l2-block

echo "export L1_HEAD=${L1_HEAD}" >> "${FILENAME}"
echo "export L2_HEAD=${L2_HEAD}" >> "${FILENAME}"
echo "export L2_BLOCK_NUMBER=${L2_BLOCK_NUMBER}" >> "${FILENAME}"
echo "export STARTING_OUTPUT_ROOT=${STARTING_OUTPUT_ROOT}" >> "${FILENAME}"
echo "export L2_CLAIM=${L2_CLAIM}" >> ${FILENAME}
echo "export OP_PROGRAM_DATA_DIR=${OP_PROGRAM_DATA_DIR}" >> "${FILENAME}"
echo "export L1_RPC=${L1_RPC}" >> "${FILENAME}"
echo "export L2_RPC=${L2_RPC}" >> "${FILENAME}"
echo "export L1_BEACON_RPC=${L1_BEACON_RPC}" >> "${FILENAME}"

echo "${FILENAME}"
