[![CI](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml/badge.svg)](https://github.com/o1-labs/proof-systems/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/o1-labs/proof-systems/status.svg?style=flat-square)](https://deps.rs/repo/github/o1-labs/proof-systems)

# Kimchi

This repository contains **kimchi**, a general-purpose zero-knowledge proof system for proving the correct execution of programs.

You can read more about this project on the [Kimchi book](https://o1-labs.github.io/proof-systems).

[See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

## Example

We assume that you already have:

* `gates`: a circuit, which can be expressed as a vector of [CircuitGate](https://o1-labs.github.io/proof-systems/rustdoc/kimchi/circuits/gate/struct.CircuitGate.html)
* a way to produce a `witness`, which can be expressed as a `[Vec<F>; COLUMNS]` (for `F` some field of your chosing)
* `public_size`: the size of the public input

Then, you can create an URS for your circuit in the following way:

```rust
use std::sync::Arc;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use circuit_construction::*;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use kimchi::verifier::verify;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    constants::*,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

pub fn circuit<
    F: PrimeField + FftField,
    Sys: Cs<F>,
>(
    witness: Option<F>,
    sys: &mut Sys,
    public_input: Vec<Var<F>>,
) {
    let three = sys.constant(3u32.into());
    let first_public_input = public_input[0];
    let witness = sys.var(|| witness.unwrap());

    //TODO replace the following free variable once the "add" gate constraint is ready to use.
    let result = sys.var(|| {
        first_public_input.val() + witness.val()
    });
    sys.assert_eq(result, three);
}

// create SRS
let srs = {
    //TODO how to determine depth value? it throws error when the depth is too large
    let mut srs = SRS::<Affine>::create(1 << 3); // 2^3 = 8
    srs.add_lagrange_basis(D::new(srs.g.len()).unwrap());
    Arc::new(srs)
};
let public_inputs = vec![1i32.into()];
let group_map = <Affine as CommitmentCurve>::Map::setup();

// generate circuit and index
let prover_index = generate_prover_index::<FpInner, _>(
    //TODO do these arguments have to be provided?
    srs,
    &fp_constants(),
    &oracle::pasta::fq_kimchi::params(),
    //TODO should this be encapsulated?
    public_inputs.len(),
    |sys, p| circuit::<_, _>(None, sys, p),
);

// create witness
let witness = 2i32;

// generate proof
let proof = prove::<Affine, _, SpongeQ, SpongeR>(
    &prover_index,
    &group_map,
    None,
    public_inputs,
    |sys, p| circuit::<Fp, _>(Some(witness.into()), sys, p),
);

// verify proof
let verifier_index = prover_index.verifier_index();
verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof).unwrap();
```

Note that kimchi is specifically designed for use in a recursion proof system, like [pickles](https://medium.com/minaprotocol/meet-pickles-snark-enabling-smart-contract-on-coda-protocol-7ede3b54c250), but can also be used a stand alone for normal proofs.

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
