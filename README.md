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

```rust,ignore
use kimchi::circuits::constraints;
use mina_curves::pasta::{fp::Fp, vesta::{Affine, VestaParameters}, pallas::Affine as Other};
use oracle::{
    poseidon::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use commitment_dlog::commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// compile the circuit
let fp_sponge_params = oracle::pasta::fp_kimchi::params();
let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, public_size).unwrap();

// create an URS
let mut urs = SRS::<Affine>::create(cs.domain.d1.size as usize);
srs.add_lagrange_basis(cs.domain.d1);

// obtain a prover index
let prover_index = {
    let fq_sponge_params = oracle::pasta::fq_kimchi::params();
    let (endo_q, _endo_r) = endos::<Other>();
    Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
};

// obtain a verifier index
let verifier_index = prover_index.verifier_index();

// create a proof
let group_map = <Affine as CommitmentCurve>::Map::setup();
let proof = { 
    // for recursion
    let k = ceil_log2(index.srs.g.len());
    let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
    let comm = {
        let coeffs = b_poly_coefficients(&chals);
        let b = DensePolynomial::from_coefficients_vec(coeffs);
        index.srs.commit_non_hiding(&b, None)
    };
    (chals, comm)
    ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &prover_index, vec![prev])
};

// verify a proof
batch_verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &[(verifier_index, proof)]).unwrap();
```

Note that kimchi is specifically designed for use in a recursion proof system, like [pickles](https://medium.com/minaprotocol/meet-pickles-snark-enabling-smart-contract-on-coda-protocol-7ede3b54c250), but can also be used a stand alone for normal proofs.

## Organization

The project is organized in the following way:

* [book/](https://github.com/o1-labs/proof-systems/tree/master/book). The mina book, RFCs, and specifications.
* [cairo/](https://github.com/o1-labs/proof-systems/tree/master/cairo). A Cairo runner written in rust.
* [curves/](https://github.com/o1-labs/proof-systems/tree/master/curves). The elliptic curves we use (for now just the pasta curves).
* [groupmap/](https://github.com/o1-labs/proof-systems/tree/master/groupmap). Used to convert elliptic curve elements to field elements.
* [kimchi/](https://github.com/o1-labs/proof-systems/tree/master/kimchi). Our proof system.
* [ocaml/](https://github.com/o1-labs/proof-systems/tree/master/ocaml). Ocaml bindings generator tool.
* [oracle/](https://github.com/o1-labs/proof-systems/tree/master/oracle). Implementation of the poseidon hash function.
* [poly-commitment/](https://github.com/o1-labs/proof-systems/tree/master/poly-commitment). Polynomial commitment code.
* [signer/](https://github.com/o1-labs/proof-systems/tree/master/signer). Implementation of schnorr signature scheme.
* [tools/](https://github.com/o1-labs/proof-systems/tree/master/tools). Various tooling to help us work on kimchi.
* [utils/](https://github.com/o1-labs/proof-systems/tree/master/utils). Collection of useful functions and traits.
