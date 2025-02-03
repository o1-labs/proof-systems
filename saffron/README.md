# Saffron - a solution for mutable state management for Web3

This crate provides a binary (`saffron`) and utilities to manage efficiently a
mutable state using succinct proofs (SNARK).

## Binary

Current Features
- Encode and decode data into polynomials.
- Compute a commitment for given input data.
- Create a storage proof for given data.
- Verify the correctness of a storage proof.

## Usage

Run `cargo run --release --bin saffron -- --help` for the list of features with the appropriate arguments.

## Test

We provide an e2e test showing all the features executed sequentially in
`./test-encoding.sh`. Use `./test-encoding.sh fixtures/lorem.txt`.

## Resources

### Introduction

- [Introducing \[Project Untitled\]: Solving Web3’s State Management Problem]((https://www.o1labs.org/blog/introducing-project-untitled))
- [Why Should Developers Have to Compromise on Web3 State Management?](https://www.o1labs.org/blog/project-untitled-technical-vision)
- [The Technical Foundations of [Project Untitled]](https://www.o1labs.org/blog/future-of-decentralized-trustless-apps)
- [Brandon Kase | Proof Singularity | ZK Taipei](https://www.youtube.com/watch?v=RE6Iyxyu0iI)

## License

This project is licensed under the Apache License - see the [../LICENSE] file
for details.
