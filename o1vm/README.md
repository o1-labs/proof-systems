# o1VM: a zero-knowledge virtual machine

This crate contains an implementation of different components used to build a
zero-knowledge virtual machine. For now, the implementation is specialised for
the ISA MIPS used by [Cannon](https://github.com/ethereum-optimism/cannon). In
the future, the codebase will be generalised to handle more ISA and more
programs.

## Description

The current version of o1vm depends on an Optimism infrastructure to fetch
blocks and transaction data (see [README-optimism.md](./README-optimism.md)).
Currently, the only program that the codebase has been tested on is the
[op-program](./ethereum-optimism/op-program), which contains code to verify
Ethereum state transitions (EVM).

`op-program` is first compiled into MIPS, using the Go compiler.
From there, we fetch the latest Ethereum/Optimism network information (latest
block, etc), and execute the op-program using the MIPS VM provided by Optimism,
named Cannon (`./run-cannon`).

We can execute o1vm later using `run-vm.sh`. It will build the whole data
points (witness) required to make a proof later.
Note that everything is only local at the moment. Nothing is posted on-chain or
anywhere else.

Each different step can be run using `./run-code.sh`.

## Pre-requisites

o1vm compiles a certain version of the Optimism codebase (written in Go), and
therefore you need to have a Go compiler installed on your machine. For now,
at least go 1.21 is required.

You can use [gvm](https://github.com/moovweb/gvm) to install a Go compiler.
Switch to go 1.21 before continuing.

```shell
gvm install go1.21
gvm use go1.21 [--default]
```

If you do not have a go version installed you will need earlier versions
to install 1.21

```shell
gvm install go1.4 -B
gvm use go1.4
export GOROOT_BOOTSTRAP=$GOROOT
gvm install go1.17.13
gvm use go1.17.13
export GOROOT_BOOTSTRAP=$GOROOT
gvm install go1.21
gvm use go1.21s
```

You also will need to install the [Foundry](https://getfoundry.sh/) toolkit
in order to utilize applications like `cast`.

```shell
foundryup
```

You will also need to install jq with your favorite packet manager.

eg. on Ubuntu

```shell
sudo apt-get install jq
```

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

## Flavors

Different versions/flavors of the o1vm are available.

- [pickles](./src/pickles/mod.rs) (currently the default)

You can select the flavor you want to run with `run-code.sh` by using the
environment variable `O1VM_FLAVOR`.

## Testing the preimage read

Run:

```bash
./test_preimage_read.sh [OP_DB_DIRECTORY] [NETWORK_NAME]
```

The default value for `OP_DB_DIRECTORY` would be the one from
`setenv-for-latest-l2-block.sh` if the parameter is omitted.

The `NETWORK_NAME` defaults to `sepolia`.

## Running the o1vm with cached data

If you want to run the o1vm with cached data, you can use the following steps:

- Make sure you have [Docker Engine](https://docs.docker.com/engine/install/) and [Python3](https://www.python.org/downloads/) installed on your machine.
- Fetch the cached data by executing the following command (it might take some time):

```shell
./fetch-e2e-testing-cache.sh
```

- Start the simple HTTP server (in background or in another terminal session):

```shell
python3 -m http.server 8765 &
```

- Then run the o1vm with the following command:

```shell
RUN_WITH_CACHED_DATA="y" FILENAME="env-for-latest-l2-block.sh" O1VM_FLAVOR="pickles" STOP_AT="=3000000" ./run-code.sh
```

- Don't forget to stop the HTTP server after you are done.

- You can clean the cached data by executing the following command:

```shell
./clear-e2e-testing-cache.sh
```

## Running test programs

Different programs written either in Rust or directly in assembly are given in
the folder `resources/programs`. For each different architecture, you can see
examples.

As installing the toolchain for each ISA might not be easy on every development
platform, we do provide the source code and the corresponding assembly
respectively in `resources/programs/[ISA]/src` and
`resources/programs/[ISA]/bin`.

### RISC-V 32 bits (riscv32i, riscv32im)

For the RISC-V 32 bits architecture, the user can install the toolchain by using
`make setup-riscv32-toolchain`.

If you encounter any issue with the build dependencies, you can refer to [this
GitHub repository](https://github.com/riscv-collab/riscv-gnu-toolchain?tab=readme-ov-file#prerequisites).

The toolchain will be available in the directory
`_riscv32-gnu-toolchain/build` at the root of this repository (see variable
`RISCV32_TOOLCHAIN_PATH` in the [Makefile](../Makefile).

To compile on of the source files available in
`resources/programs/riscv32im/src`, the user can use:

```shell
FILENAME=sll.S

_riscv32-gnu-toolchain/build/bin/riscv32-unknown-elf-as
  -o a.out \
  o1vm/resources/programs/riscv32im/src/${FILENAME}
```

### Write new test examples

The Makefile at the top-level of this repository will automatically detect new
`.S` files in the directory `o1vm/resources/programs/riscv32im/src/` when the
target `build-riscv32-programs` is called. Any change to the existing files will
also be detected by the target, and you can commit the changes of the resulting
binary.

## License

This project is dual-licensed under either:

* MIT license (see LICENSE-MIT)
* Apache License, Version 2.0 (see LICENSE-APACHE)

at your option.

Copyright (c) 2022-2025 o1Labs
