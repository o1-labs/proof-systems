[![CI](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml/badge.svg)](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/o1-labs/proof-systems/status.svg?style=flat-square)](https://deps.rs/repo/github/o1-labs/proof-systems)

# Kimchi

This repository contains **kimchi**, a general-purpose zero-knowledge proof system for proving the correct execution of programs.

You can read more about this project on the [Kimchi book](https://o1-labs.github.io/proof-systems), or for a lighter introduction in this [blogpost](https://minaprotocol.com/blog/kimchi-the-latest-update-to-minas-proof-system).

[See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

## User Warning

This project comes as is. We provide no guarantee of stability or support, as the crates closely follow the needs of the [Mina]([https://](https://github.com/minaprotocol/mina)) project.

If you use this project in a production environment, it is your responsibility to perform a security audit to ensure that the software meets your requirements.

## Performance

At the time of this writing:

**Proving time**

| number of gates | seconds |
| :-------------: | :-----: |
|      2^11       |  0.6s   |
|      2^15       |  3.3s   |
|      2^16       |  6.3s   |

**Verification time**

| number of gates | seconds |
| :-------------: | :-----: |
|      2^15       |  0.1s   |
|      2^16       |  0.1s   |

**Proof size**

| number of gates | bytes |
| :-------------: | :---: |
|      2^15       | 4947  |
|      2^16       | 5018  |

## Organization

The project is organized in the following way:

* [book/](book/). The mina book, RFCs, and specifications. [Available here in HTML](https://o1-labs.github.io/proof-systems).
* [curves/](curves/). The elliptic curves we use (for now just the pasta curves).
* [groupmap/](groupmap/). Used to convert elliptic curve elements to field elements.
* [hasher/](hasher/). Interfaces for mina hashing.
* [kimchi/](kimchi/). Our proof system based on PLONK.
* [poly-commitment/](poly-commitment/). Polynomial commitment code.
* [poseidon/](poseidon/). Implementation of the poseidon hash function.
* [signer/](signer/). Interfaces for mina signature schemes.
* [tools/](tools/). Various tooling to help us work on kimchi.
* [turshi/](turshi/). A Cairo runner written in rust.
* [utils/](utils/). Collection of useful functions and traits.

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) if you are interested in contributing to this project.
