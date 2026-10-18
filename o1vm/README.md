# o1VM: a zero-knowledge virtual machine

This crate contains an implementation of different components used to build a
zero-knowledge virtual machine. For now, the implementation is specialised for
the ISA MIPS used by [Cannon](https://github.com/ethereum-optimism/cannon). In
the future, the codebase will be generalised to handle more ISA and more
programs.

## Description

The o1vm executes MIPS programs following the semantics of Cannon, the MIPS VM
of Optimism. It was tested on
[op-program](https://github.com/ethereum-optimism/optimism/tree/develop/op-program),
which verifies Ethereum state transitions (EVM). The Optimism codebase is no
longer vendored in this repository: to run op-program through the o1vm, build it
from the Optimism repository and put the `op-program` binary on your `PATH`.

Fetching blocks and transaction data requires an Optimism infrastructure (see
[README-optimism.md](./README-optimism.md)).

## Pre-requisites

The helper scripts `setenv-for-l2-block.sh`, `setenv-for-latest-l2-block.sh` and
`test_preimage_read.sh` need the [Foundry](https://getfoundry.sh/) toolkit (for
`cast`) and `jq`, and an executable `rpcs.sh` file like:

```bash
#!/usr/bin/env bash
export L1_RPC=http://xxxxxxxxx
export L2_RPC=http://xxxxxxxxx
export OP_NODE_RPC=http://xxxxxxxxx
export L1_BEACON_RPC=http://xxxxxxxxx
```

To generate the environment for the state transition between a given L2 block
and its predecessor:

```bash
./setenv-for-l2-block.sh -n 12826645
```

## Flavors

Different versions/flavors of the o1vm are available.

- [pickles](./src/pickles/mod.rs) (currently the default)

## Testing the preimage read

Run:

```bash
./test_preimage_read.sh [OP_DB_DIRECTORY] [NETWORK_NAME]
```

The default value for `OP_DB_DIRECTORY` would be the one from
`setenv-for-latest-l2-block.sh` if the parameter is omitted.

The `NETWORK_NAME` defaults to `sepolia`.

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

If you encounter any issue with the build dependencies, you can refer to
[this GitHub repository](https://github.com/riscv-collab/riscv-gnu-toolchain?tab=readme-ov-file#prerequisites).

The toolchain will be available in the directory `_riscv32-gnu-toolchain/build`
at the root of this repository (see variable `RISCV32_TOOLCHAIN_PATH` in the
[Makefile](../Makefile).

To compile on of the source files available in
`resources/programs/riscv32im/src`, the user can use:

```shell
FILENAME=sll.S

_riscv32-gnu-toolchain/build/bin/riscv32-unknown-elf-as
  -o a.out \
  o1vm/resources/programs/riscv32im/src/${FILENAME}
```

### MIPS (open MIPS tests)

The MIPS test programs are the OpenMIPS test vectors from the Optimism
repository (licensed LGPLv3, so they are not copied into this repository). They
are reached through the `ethereum-optimism` submodule, of which only
`cannon/mipsevm/open_mips_tests` is fetched:

```shell
make setup-open-mips-tests
```

Then `make build-mips-programs` converts them into `resources/programs/mips/src`
and assembles them into `resources/programs/mips/bin`, using
`binutils-mips-linux-gnu`.

### Write new test examples

The Makefile at the top-level of this repository will automatically detect new
`.S` files in the directory `o1vm/resources/programs/riscv32im/src/` when the
target `build-riscv32-programs` is called. Any change to the existing files will
also be detected by the target, and you can commit the changes of the resulting
binary.

## License

This project is dual-licensed under either:

- MIT license (see LICENSE-MIT)
- Apache License, Version 2.0 (see LICENSE-APACHE)

at your option.

Copyright (c) 2022-2025 o1Labs
