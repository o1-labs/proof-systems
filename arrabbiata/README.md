# Arrabbiata

A generic recursive zero-knowledge argument implementation based on folding
schemes.

## Motivation

This library provides an implementation of a generic recursive zero-knowledge
argument based on folding schemes (initially defined in
[Nova](https://eprint.iacr.org/2021/370)), over the
[pasta](https://github.com/zcash/pasta_curves) curves and using the IPA
polynomial commitment.

The end goal of this repository is to implement a Nova-like prover, and have a
zkApp on the Mina blockchain verifying the recursive proof*. This way, any user
can run arbitrarily large computation on their machine, make a proof, and rely
on the SNARK workers to verify the proof is correct and include it on-chains.

The first iteration of the project will allow to fold a polynomial `f` (which
can be, in a near future, a zkApp), of degree 2**. No generic lookup argument
will be implemented in the first version, even though a "runtime"
lookup/permutation argument will be required for cross-cells referencing. The
implementation leverages different constructions and ideas described in papers
like [ProtoGalaxy](https://eprint.iacr.org/2023/1106),
[ProtoStar](https://eprint.iacr.org/2023/620), etc.

*This might need changes to the Mina blockchain, with a possible new hardfork.
Not even sure it is possible right now.

**This will change. We might go up to degree 6 or 7, as we're building the
different gadgets (EC addition, EC scalar multiplication, Poseidon).

## Implementation details

We provide a binary to run arbitrarily large computation. The implementation
of the circuits will follow the one used by the o1vm interpreter. An
interpreter will be implemented over an abstract environment.

The environment used for the witness will contain all the information required
to make an IVC proof, i.e. the current witness in addition to the oracle, the
folding accumulator, etc. And the implementation attempts to have the smallest
memory footprint it can have by optimising the use of the CPU cache and using
references as much as it can. The implementation attempts to prioritize
allocations on the stack when possible, and attempts to keep in the CPU cache
as many data as required as long as possible to avoid indirection.

The witness interpreter attempts to perform most of the algebraic operations
using integers, and not field element. The results are reduced into the field
when mandatory.

While building the witness, the cross terms are also computed on the fly, to
be used in the next iteration. This way, the prover only pays the price of the
activated gate on each row.

## Usage

### List available circuits

```bash
cargo run --bin arrabbiata --release -- execute --list-circuits
```

This will show all registered circuits with their properties:

- `trivial`: Identity circuit z_{i+1} = z_i
- `squaring`: Squaring circuit z_{i+1} = z_i^2
- `repeated-squaring`: 2^15 squarings per fold (requires --srs-size 15)
- `cubic`: Cubic circuit z_{i+1} = z_i^3 + z_i + 5
- `square-cubic`: Composed circuit x -> x^6 + x^2 + 5
- `fibonacci`: Fibonacci sequence (x, y) -> (y, x + y)
- `repeated-fibonacci`: 2^15 Fibonacci steps per fold (requires --srs-size 15)
- `counter`: Counter circuit z_{i+1} = z_i + 1
- `minroot`: MinRoot VDF computing 5th roots
- `hashchain`: Hash chain z_{i+1} = hash(z_i)

### Run a circuit

```bash
# Run 10 iterations of the squaring circuit with SRS size 2^8
RUST_LOG=info cargo run --bin arrabbiata --release -- \
    execute --circuit squaring -n 10 --srs-size 8

# Run the Fibonacci circuit for 5 iterations
RUST_LOG=info cargo run --bin arrabbiata --release -- \
    execute --circuit fibonacci -n 5 --srs-size 8

# Run the cubic circuit
RUST_LOG=info cargo run --bin arrabbiata --release -- \
    execute --circuit cubic -n 10 --srs-size 8

# Run repeated-squaring with large SRS (2^15 squarings per fold)
RUST_LOG=info cargo run --bin arrabbiata --release -- \
    execute --circuit repeated-squaring -n 2 --srs-size 15
```

The output includes timing information for:

- Setup phase (SRS generation)
- Folding phase (N iterations)
- Proof generation
- Verification (structure check)

You can activate verbose logging with `RUST_LOG=debug`.

## Run tests

```bash
cargo nextest run --all-features --release --nocapture -p arrabbiata
```

## Circuit Registry

The library provides a `CircuitRegistry` for managing available circuits. The
registry can be found in `src/registry.rs`.

To implement a custom circuit, implement the `StepCircuit` trait:

```rust
use arrabbiata::circuit::{CircuitEnv, StepCircuit};
use ark_ff::PrimeField;

pub struct MyCircuit<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> StepCircuit<F, 1> for MyCircuit<F> {
    fn synthesize<E: CircuitEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; 1],
    ) -> [E::Variable; 1] {
        // Define your circuit constraints here
        let output = env.alloc_witness(F::zero());
        // ... add constraints ...
        [output]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        // Compute the output for witness generation
        [z[0]] // Replace with actual computation
    }
}
```

Example circuits are provided in `src/circuits/`.

## References

- The name is not only used as a reference to Kimchi and Pickles, but also to
  the mathematician [Aryabhata](https://en.wikipedia.org/wiki/Aryabhata).

## Related Implementations

Other folding scheme implementations that served as inspiration:

- [Microsoft Nova](https://github.com/microsoft/Nova) - The original Nova
  implementation in Rust
- [PSE Folding Schemes (Sonobe)](https://github.com/privacy-scaling-explorations/folding-schemes) -
  Experimental arkworks library for different folding schemes
- [Snarkify Sirius](https://github.com/snarkify/sirius) - Plonkish folding
  framework for IVC
- [ProtoGalaxy PoC](https://github.com/arnaucube/protogalaxy-poc) - ProtoGalaxy
  proof of concept using arkworks
- [Geometry ProtoStar](https://github.com/geometryxyz/protostar) - ProtoStar
  implementation for halo2-PSE
- [LatticeFold](https://github.com/NethermindEth/latticefold) - Lattice-based
  folding schemes
- [Awesome Folding](https://github.com/lurk-lab/awesome-folding) - Curated list
  of zero-knowledge folding schemes

## Resources

### Papers

- [Nova: Recursive Zero-Knowledge Arguments from Folding Schemes](https://eprint.iacr.org/2021/370)
- [ProtoStar: Generic Efficient Accumulation/Folding for Special Sound Protocols](https://eprint.iacr.org/2023/620)
- [ProtoGalaxy: Efficient ProtoStar-style folding of multiple instances](https://eprint.iacr.org/2023/1106)
- [Behind Nova: cross-terms computation for high degree gates](https://hackmd.io/qq_Awc1AR3ywzkruE4Wq9Q)
- [CycleFold: Folding-scheme-based recursive arguments over a cycle of elliptic curves](https://eprint.iacr.org/2023/1192)
- [Revisiting the Nova Proof System on a Cycle of Curves](https://eprint.iacr.org/2023/969)
