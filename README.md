[![CI](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml/badge.svg)](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/o1-labs/proof-systems/status.svg?style=flat-square)](https://deps.rs/repo/github/o1-labs/proof-systems)

# Kimchi

This repository contains **kimchi**, a general-purpose zero-knowledge proof system for proving the correct execution of programs.

You can read more about this project on the [Kimchi book](https://o1-labs.github.io/proof-systems).

[See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

# Kombucha

This repository contains **kombucha**, the Kimchi circuit constructor for external users.

## Guidelines

When using this library, make sure to include in your Cargo.toml the following dependency:

```toml
[dependencies]
circuit-construction = { git = "https://github.com/o1-labs/proof-systems" }
```

## Example

The following is an example to demonstrate a full cycle workflow using circuit-construction:

1. Specify a circuit
2. Create SRS
3. Generate prover index
4. Generate a proof
5. Verify the proof

```rust
use circuit_construction::{prologue::*};

type SpongeQ<'a> = DefaultFqSponge<'a, VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR<'a> = DefaultFrSponge<'a, Fp, PlonkSpongeConstantsKimchi>;

// a callback function to specify constraint gates for a circuit
pub fn circuit<
    F: PrimeField + FftField,
    Sys: Cs<F>,
>(
    witness: Option<F>,
    sys: &mut Sys,
    public_input: Vec<Var<F>>,
) {
    // add a constant gate
    let three = sys.constant(3u32.into());
    // read the first public input
    let first_public_input = public_input[0];
    // create a free variable to hold a witness value
    let witness = sys.var(|| witness.unwrap());

    // create a free variable to hold a calculation result
    let result = sys.var(|| {
        first_public_input.val() + witness.val()
    });

    // add a gate to assert the calculation equals to a constant constraint
    sys.assert_eq(result, three);
}

// create SRS
let srs = {
    let mut srs = SRS::<VestaAffine>::create(1 << 3); // 2^3 = 8
    srs.add_lagrange_basis(Radix2EvaluationDomain::new(srs.g.len()).unwrap());
    Arc::new(srs)
};
let public_inputs = vec![1i32.into()];
let group_map = <VestaAffine as CommitmentCurve>::Map::setup();

// generate circuit and index
let prover_index = generate_prover_index::<FpInner, _>(
    srs,
    &fp_constants(),
    &oracle::pasta::fq_kimchi::params(),
    // to determine how many placeholders to generate for public inputs
    public_inputs.len(),
    // use the circuit callback to generate gate constraints 
    // with placeholders for the witness and public inputs
    |sys, p| circuit::<_, _>(None, sys, p),
);

// create witness
let witness = 2i32;

// generate proof
let proof = prove::<VestaAffine, _, SpongeQ, SpongeR>(
    &prover_index,
    &group_map,
    None,
    public_inputs,
    // use the same circuit callbacb
    // but with values for witness and public inputs
    |sys, p| circuit::<Fp, _>(Some(witness.into()), sys, p),
);

// verify proof
let verifier_index = prover_index.verifier_index();
verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof).unwrap();
```

For the other examples, please refer to the [tests](./circuit-construction/tests/).

Note that kimchi is specifically designed for use in a recursion proof system, like [pickles](https://medium.com/minaprotocol/meet-pickles-snark-enabling-smart-contract-on-coda-protocol-7ede3b54c250), but can also be used a stand alone for normal proofs.

## Performance

At the time of this writing:

**Proving time**

| number of gates | seconds |
|:---------------:|:-------:|
|       2^11      |   0.6s  |
|       2^15      |   3.3s  |
|       2^16      |   6.3s  |

**Verification time**

| number of gates | seconds |
|:---------------:|:-------:|
|       2^15      |   0.1s  |
|       2^16      |   0.1s  |

## Organization

The project is organized in the following way:

* [book/](https://github.com/o1-labs/proof-systems/tree/master/book). The mina book, RFCs, and specifications.
* [cairo/](https://github.com/o1-labs/proof-systems/tree/master/cairo). A Cairo runner written in rust.
* [circuit-construction/](https://github.com/o1-labs/proof-systems/tree/master/circuit-construction). Circuit writer.
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
