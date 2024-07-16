## Arrabiata - a Nova implementation over the Pasta curve

### Motivation

This library provides a basic implementation of the recursive zero-knowledge
arguments described in the paper [Nova](https://eprint.iacr.org/2021/370), over
the [pasta]() curves and using the IPA polynomial commitment.

The end goal of this repository is to implement a Nova prover, and have a zkApp
on the Mina blockchain verifying the Nova proof*. This way, any user can run
arbitrarily large computation on their machine, make a proof, and rely on the
SNARK workers to verify the proof is correct and include it on-chains.

The first iteration of the project will allow to fold a polynomial-time function
`f`, of degree 2. No lookup argument will be implemented in the first version.
A generalisation can be done using different constructions, like the ones
described in the [folding](../folding) library, or in papers like
[ProtoGalaxy](https://eprint.iacr.org/2023/1106),
[ProtoStar](https://eprint.iacr.org/2023/620), etc. We leave this for future
work.

*This might need changes to the Mina blockchain, with a possible new hardfork.
Not even sure it is possible right now.

### Implementation details

We provide a binary to run arbitrarily large computation.
The implementation of the circuits will follow the one used by the o1vm
interpreter. An interpreter will be implemented over an abstract environment.
The environment used for the witness will contain all the information required
to make an IVC proof, i.e. the current witness in addition to the oracle, the
folding accumulator, etc.

### Examples

Different built-in examples are provided. For instance:
```
cargo run --bin arrabiata --release -- square-root --n 10 --srs-size 16
```

will generate 10 full Nova iterations of the polynomial-time function `f(X, Y) =
X^2 - Y` and for each witness, generates random values, and make an IVC proof at
the end.

### Run tests

```
cargo nextest run --all-features --release
```
