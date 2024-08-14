## o1VM: a zero-knowledge virtual machine

This crate contains an implementation of different components used to build a
zero-knowledge virtual machine. For now, the implementation is specialised for
the ISA MIPS used by [Cannon](https://github.com/ethereum-optimism/cannon). In
the future, the codebase will be generalised to handle more ISA and more
programs.


## Pre-requisites

o1vm compiles a certain version of the Optimism codebase (written in Go), and
therefore you need to have a Go compiler installed on your machine. For now,
at least go 1.21 is required.
You can use [gvm](https://github.com/moovweb/gvm) to install a Go compiler.
Switch to go 1.21 before continuing.

## Running the Optimism demo

Start by initializing the submodules:
```bash
git submodule init && git submodule update
```

Create an executable `rpcs.sh` file like:
```bash
#!/usr/bin/env bash
export L1_RPC=http://xxxxxxxxx
export L2_RPC=http://xxxxxxxxx
export OP_NODE_RPC=http://xxxxxxxxx
export L1_BEACON_RPC=http://xxxxxxxxx
```

If you just want to test the state transition between the latest finalized L2
block and its predecessor:
```bash
./run-code.sh
```

By default this will also create a script named `env-for-latest-l2-block.sh` with a
snapshot of all the information that you need to rerun the same test again:
```bash
FILENAME=env-for-latest-l2-block.sh bash run-code.sh
```

Alternatively, you also have the option to test the state transition between a
specific block and its predecessor:
```bash
# Set -n to the desired block transition you want to test.
./setenv-for-l2-block.sh -n 12826645
```

In this case, you can run the demo using the following format:
```bash
FILENAME=env-for-l2-block-12826645.sh bash run-code.sh
```

In either case, `run-code.sh` will:
1. Generate the initial state.
2. Execute the OP program.
3. Execute the OP program through the Cannon MIPS VM.
4. Execute the OP program through the o1VM MIPS

## Testing the preimage read

Run:
```bash
./test_preimage_read.sh [OP_DB_DIRECTORY] [NETWORK_NAME]
```

The default value for `OP_DB_DIRECTORY` would be the one from
`setenv-for-latest-l2-block.sh` if the parameter is omitted.

The `NETWORK_NAME` defaults to `sepolia`.
