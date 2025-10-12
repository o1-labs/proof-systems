# Kimchi

[![codecov](https://codecov.io/gh/o1-labs/proof-systems/graph/badge.svg?token=pl6W1FDfV0)](https://codecov.io/gh/o1-labs/proof-systems)

[![CI](https://github.com/o1-labs/proof-systems/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/o1-labs/proof-systems/actions/workflows/ci.yml)
[![CI nightly](https://github.com/o1-labs/proof-systems/actions/workflows/ci-nightly.yml/badge.svg?branch=master)](https://github.com/o1-labs/proof-systems/actions/workflows/ci-nightly.yml)
[![GitHub page](https://github.com/o1-labs/proof-systems/actions/workflows/gh-page.yml/badge.svg?branch=master)](https://github.com/o1-labs/proof-systems/actions/workflows/gh-page.yml)
[![o1vm CI](https://github.com/o1-labs/proof-systems/actions/workflows/o1vm-ci.yml/badge.svg?branch=master)](https://github.com/o1-labs/proof-systems/actions/workflows/o1vm-ci.yml)

[![dependency status](https://deps.rs/repo/github/o1-labs/proof-systems/status.svg?style=flat-square)](https://deps.rs/repo/github/o1-labs/proof-systems)

This repository contains **kimchi**, a general-purpose zero-knowledge proof system for proving the correct execution of programs.

You can read more about this project on the [Kimchi book](https://o1-labs.github.io/proof-systems), or for a lighter introduction in this [blogpost](https://minaprotocol.com/blog/kimchi-the-latest-update-to-minas-proof-system).

[See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

## User Warning

This project comes as is. We provide no guarantee of stability or support, as the crates closely follow the needs of the [Mina](<[https://](https://github.com/minaprotocol/mina)>) project.

If you use this project in a production environment, it is your responsibility to perform a security audit to ensure that the software meets your requirements.

## Performance

At the time of this writing:

### Proving time

| number of gates | seconds |
| :-------------: | :-----: |
|      2^11       |  0.6s   |
|      2^15       |  3.3s   |
|      2^16       |  6.3s   |

### Verification time

| number of gates | seconds |
| :-------------: | :-----: |
|      2^15       |  0.1s   |
|      2^16       |  0.1s   |

### Proof size

| number of gates | bytes |
| :-------------: | :---: |
|      2^15       | 4947  |
|      2^16       | 5018  |

## Organization

The project is organized in the following way:

- [book/](book/). The mina book, RFCs, and specifications. [Available here in HTML](https://o1-labs.github.io/proof-systems).
- [curves/](curves/). The elliptic curves we use (for now just the pasta curves).
- [groupmap/](groupmap/). Used to convert elliptic curve elements to field elements.
- [hasher/](hasher/). Interfaces for mina hashing.
- [kimchi/](kimchi/). Our proof system based on PLONK.
- [poly-commitment/](poly-commitment/). Polynomial commitment code.
- [poseidon/](poseidon/). Implementation of the poseidon hash function.
- [signer/](signer/). Interfaces for mina signature schemes.
- [tools/](tools/). Various tooling to help us work on kimchi.
- [turshi/](turshi/). A Cairo runner written in rust.
- [utils/](utils/). Collection of useful functions and traits.

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) if you are interested in contributing to this project.

## Generate rustdoc locally

An effort is made to have the documentation being self-contained, referring to the mina book for more details when necessary.
You can build the rust documentation with

<!-- This must be the same than the content in .github/workflows/gh-page.yml -->

```shell
rustup install nightly
RUSTDOCFLAGS="--enable-index-page -Zunstable-options" cargo +nightly doc --all --no-deps
```

You can visualize the documentation by opening the file `target/doc/index.html`.

## CI

<!-- Please update this section if you add more workflows -->

- [CI](.github/workflows/ci.yml).
  This workflow ensures that the entire project builds correctly, adheres to guidelines, and passes all necessary tests.
- [Nightly tests with the code coverage](.github/workflows/ci-nightly.yml).
  This workflow runs all the tests per scheduler or on-demand, generates and attaches the code coverage report to the job's execution results.
- [Benchmarks](.github/workflows/benches.yml).
  This workflow runs benchmarks when a pull request is labeled with "benchmark." It sets up the Rust and OCaml environments, installs necessary tools, and executes cargo criterion benchmarks on the kimchi crate. The benchmark results are then posted as a comment on the pull request for review.
- [Deploy Specifications & Docs to GitHub Pages](.github/workflows/gh-page.yml).
  When CI passes on master, the documentation built from the rust code will be available by this [link](https://o1-labs.github.io/proof-systems/rustdoc) and the book will be available by this [link](https://o1-labs.github.io/proof-systems).
- [MIPS Build and Package](https://github.com/o1-labs/proof-systems/blob/master/.github/workflows/o1vm-upload-mips-build.yml)
  This workflow runs the assembler and linker on the programs from the OpenMips test suite, and provides a link where you can download the artifacts (recommended if you don't have / can't install the required MIPS tooling). This workflow also runs the o1vm ELF parser on the artifacts to check that our parsing is working. Currently it is run via manual trigger only -- you can find the trigger in the [GitHub actions tab](https://github.com/o1-labs/proof-systems/actions/workflows/mips-build.yml) and the link to the artifacts will appear in logs of the `Upload Artifacts` stage.

## Nix for Dependencies (WIP)

If you have `nix` installed and in particular, `flakes` enabled, you can install the dependencies for these projects using nix. Simply `nix develop .` inside this directory to bring into scope `rustup`, `opam`, and `go` (along with a few other tools). You will have to manage the toolchains yourself using `rustup` and `opam`, in the current iteration.
