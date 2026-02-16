#!/bin/bash

while getopts ":n:" opt; do
    case "$opt" in
    n)  L2_BLOCK_NUMBER=$OPTARG
        ;;
    *)
        echo "Usage: $0 -n L2_BLOCK_NUMBER" 1>&2
        exit 0
        ;;
    esac
done

shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ -z "${L2_BLOCK_NUMBER}" ]; then
    # You can check for a block at:
    # https://sepolia-optimism.etherscan.io/block/L2_BLOCK_NUMBER
   echo "Usage: $0 -n L2_BLOCK_NUMBER" 1>&2
   exit 0
fi

re='^[0-9]+$'
if ! [[ $L2_BLOCK_NUMBER =~ $re ]] ; then
   echo "The -n argument must be a number" 1>&2
   exit 0
fi

source rpcs.sh

OUTPUT_L2_BLOCK=$(cast rpc optimism_outputAtBlock $(cast th $L2_BLOCK_NUMBER) --rpc-url "${OP_NODE_RPC}")
OUTPUT_L2_PREVIOUS_BLOCK=$(cast rpc optimism_outputAtBlock $(cast th $((L2_BLOCK_NUMBER-1))) --rpc-url "${OP_NODE_RPC}")

# We use the STARTING_OUTPUT_ROOT as the output state just prior to the
# L2_BLOCK_NUMBER
STARTING_OUTPUT_ROOT=$(echo $OUTPUT_L2_PREVIOUS_BLOCK | jq -r .outputRoot) 

#Claim of transition between STARTING_OUTPUT_ROOT up to L2_BLOCK_NUMBER
L2_CLAIM=$(echo $OUTPUT_L2_BLOCK | jq -r .outputRoot) 

# Get the finalized heads
L1_HEAD=$(echo $OUTPUT_L2_BLOCK | jq -r .blockRef.l1origin.hash)
L2_HEAD=$(echo $OUTPUT_L2_PREVIOUS_BLOCK | jq -r .blockRef.hash)

echo "The claim of the transition to block ${L2_BLOCK_NUMBER} is $L2_CLAIM" 1>&2

FILENAME=env-for-l2-block-${L2_BLOCK_NUMBER}.sh
# Delete all lines in the file if it already exists
cat /dev/null > ${FILENAME}

OP_PROGRAM_DATA_DIR=$(pwd)/op-program-db-for-l2-block-${L2_BLOCK_NUMBER}

echo "export L1_HEAD=${L1_HEAD}" >> "${FILENAME}"
echo "export L2_HEAD=${L2_HEAD}" >> "${FILENAME}"
echo "export L2_BLOCK_NUMBER=${L2_BLOCK_NUMBER}" >> "${FILENAME}"
echo "export STARTING_OUTPUT_ROOT=${STARTING_OUTPUT_ROOT}" >> "${FILENAME}"
echo "export L2_CLAIM=${L2_CLAIM}" >> ${FILENAME}
echo "export OP_PROGRAM_DATA_DIR=${OP_PROGRAM_DATA_DIR}" >> "${FILENAME}"
echo "export L1_RPC=${L1_RPC}" >> "${FILENAME}"
echo "export L2_RPC=${L2_RPC}" >> "${FILENAME}"
echo "export L1_BEACON_RPC=${L1_BEACON_RPC}" >> "${FILENAME}"


# echo "Env variables for block ${L2_BLOCK_NUMBER} can be loaded using
# ./${FILENAME}"
echo "${FILENAME}"
