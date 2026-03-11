# Arrabbiata - a generic recursive zero-knowledge argument implementation based on folding schemes

## Motivation

This library provides an implementation of a generic recursive zero-knowledge
argument based on folding schemes (initially defined in
[Nova](https://eprint.iacr.org/2021/370)), over the
[pasta](https://github.com/zcash/pasta_curves) curves and using the IPA
polynomial commitment.

The end goal of this repository is to implement a Nova-like prover, and have a
zkApp on the Mina blockchain verifying the recursive proof\*. This way, any user
can run arbitrarily large computation on their machine, make a proof, and rely
on the SNARK workers to verify the proof is correct and include it on-chains.

The first iteration of the project will allow to fold a polynomial `f` (which
can be, in a near future, a zkApp), of degree 2\*\*. No generic lookup argument
will be implemented in the first version, even though a "runtime"
lookup/permutation argument will be required for cross-cells referencing. The
implementation leverages different constructions and ideas described in papers
like [ProtoGalaxy](https://eprint.iacr.org/2023/1106),
[ProtoStar](https://eprint.iacr.org/2023/620), etc.

\*This might need changes to the Mina blockchain, with a possible new hardfork.
Not even sure it is possible right now.

\*\*This will change. We might go up to degree 6 or 7, as we're building the
different gadgets (EC addition, EC scalar multiplication, Poseidon).

## Implementation details

We provide a binary to run arbitrarily large computation. The implementation of
the circuits will follow the one used by the o1vm interpreter. An interpreter
will be implemented over an abstract environment.

The environment used for the witness will contain all the information required
to make an IVC proof, i.e. the current witness in addition to the oracle, the
folding accumulator, etc. And the implementation attempts to have the smallest
memory footprint it can have by optimising the use of the CPU cache and using
references as much as it can. The implementation attempts to prioritize
allocations on the stack when possible, and attempts to keep in the CPU cache as
many data as required as long as possible to avoid indirection.

The witness interpreter attempts to perform most of the algebraic operations
using integers, and not field element. The results are reduced into the field
when mandatory.

While building the witness, the cross terms are also computed on the fly, to be
used in the next iteration. This way, the prover only pays the price of the
activated gate on each row.

## Examples

Different built-in examples are provided. For instance:

```
RUST_LOG=debug cargo run --bin arrabbiata --release -- execute -n 10 --zkapp "square-root" --srs-size 16
```

will generate 10 full folding iterations of the function `f(X, Y) = X^2 - Y` and
for each witness, generates random values, and make an IVC proof at the end.

You can also activate logging which contains benchmarking by using the
environment variable `RUST_LOG=debug`.

## Run tests

```
cargo nextest run --all-features --release --nocapture -p arrabbiata
```

## Registry of zkApps

A registry of zkApps is already preconfigured. To write a zkApp, check TODO.

The zkApp registry can be found in TODO

<!-- The idea is to able to load at runtime a function of type <E:
InterpreterEnv> -> () which takes an environment as a parameter, and anything
can be built from there, in Rust, directly. We simply need to provide an
interface. A zkApp can use up to N columns, N being the value defined in the
lib.rs file. In this registry, we could have for instance o1VM -->

<!-- The user should also be able to switch the IVC circuit to use different
versions over time. It can also be done using a registry. We keep only one IVC
circuit for now -->

## References

- The name is not only used as a reference to Kimchi and Pickles, but also to
  the mathematician [Aryabhata](https://en.wikipedia.org/wiki/Aryabhata).

## Resources

- [Nova: Recursive Zero-Knowledge Arguments from Folding Schemes](https://eprint.iacr.org/2021/370)
- [ProtoStar: Generic Efficient Accumulation/Folding for Special Sound Protocols](https://eprint.iacr.org/2023/620)
- [ProtoGalaxy: Efficient ProtoStar-style folding of multiple instances](https://eprint.iacr.org/2023/1106)
- [Behind Nova: cross-terms computation for high degree gates](https://hackmd.io/qq_Awc1AR3ywzkruE4Wq9Q)
- [CycleFold: Folding-scheme-based recursive arguments over a cycle of elliptic curves](https://eprint.iacr.org/2023/1192)
- [Revisiting the Nova Proof System on a Cycle of Curves](https://eprint.iacr.org/2023/969)
