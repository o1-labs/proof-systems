#!/usr/bin/env bash
set -euo pipefail

make -C ./ethereum-optimism/op-program op-program

set -x
./ethereum-optimism/op-program/bin/op-program \
	--log.level DEBUG \
	--l1 "${L1_RPC}" \
	--l2 "${L2_RPC}" \
	--network sepolia \
	--datadir "${OP_PROGRAM_DATA_DIR}" \
	--l1.head "${L1_HEAD}" \
	--l1.beacon "${L1_BEACON_RPC}" \
	--l2.head "${L2_HEAD}" \
	--l2.outputroot "${STARTING_OUTPUT_ROOT}" \
	--l2.claim "${L2_CLAIM}" \
	--l2.blocknumber "${L2_BLOCK_NUMBER}"
