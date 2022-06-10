[![CI](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml/badge.svg)](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/o1-labs/proof-systems/status.svg?style=flat-square)](https://deps.rs/repo/github/o1-labs/proof-systems)

# Kimchi

This repository contains **kimchi**, a general-purpose zero-knowledge proof system for proving the correct execution of programs.

You can read more about this project on the [Kimchi book](https://o1-labs.github.io/proof-systems).

[See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

## Organization

The project is organized in the following way:

* [book/](https://github.com/o1-labs/proof-systems/tree/master/book). The mina book, RFCs, and specifications.
* [cairo/](https://github.com/o1-labs/proof-systems/tree/master/cairo). A Cairo runner written in rust.
* [curves/](https://github.com/o1-labs/proof-systems/tree/master/curves). The elliptic curves we use (for now just the pasta curves).
* [groupmap/](https://github.com/o1-labs/proof-systems/tree/master/groupmap). Used to convert elliptic curve elements to field elements.
* [hasher/](https://github.com/o1-labs/proof-systems/tree/master/hasher). Interfaces for mina hashing.
* [kimchi/](https://github.com/o1-labs/proof-systems/tree/master/kimchi). Our proof system.
* [ocaml/](https://github.com/o1-labs/proof-systems/tree/master/ocaml). Ocaml bindings generator tool.
* [oracle/](https://github.com/o1-labs/proof-systems/tree/master/oracle). Implementation of the poseidon hash function.
* [poly-commitment/](https://github.com/o1-labs/proof-systems/tree/master/poly-commitment). Polynomial commitment code.
* [signer/](https://github.com/o1-labs/proof-systems/tree/master/signer). Interfaces for mina signature schemes.
* [tools/](https://github.com/o1-labs/proof-systems/tree/master/tools). Various tooling to help us work on kimchi.
* [utils/](https://github.com/o1-labs/proof-systems/tree/master/utils). Collection of useful functions and traits.

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) if you are interested in contributing to this project.
