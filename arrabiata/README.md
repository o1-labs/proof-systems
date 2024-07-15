## Arrabiata - a Nova implementation over the Pasta curve

### Motivation

This library provides a basic implementation of the recursive zero-knowledge
arguments described in the paper [Nova](https://eprint.iacr.org/2021/370), over
the [pasta]() curves.

The end goal of this repository is to implement a Nova prover, and have a zkApp
on the Mina blockchain verifying the Nova proof*. This way, any user can run
arbitrarily large computation on their machine, make a proof, and rely on the
SNARK workers to verify the proof is correct and include it on-chains.

The first iteration of the project will allow to fold a polynomial-time function
`f`, of degree 2.
A generalisation can be done using different constructions, like the ones
described in the [folding](../folding) library, or in papers like
[ProtoGalaxy](), [ProtoStar](), etc. We leave this for future workProto.

*This might need changes to the Mina blockchain, with a possible new hardfork.
