# Kimchi

This document specifies the kimchi variant of PLONK.

## Overview

TKTK

## Dependencies

### Polynomial Commitments

Refer to the [specification on polynomial commitments](./poly-commitment.md). We make use of the following functions from that specification:

- `PolyCom.non_hiding_commit(poly) -> PolyCom::NonHidingCommitment`
- `PolyCom.commit(poly) -> PolyCom::HidingCommitment`
- `PolyCom.evaluation_proof(poly, commitment, point) -> EvaluationProof`
- `PolyCom.verify(commitment, point, evaluation, evaluation_proof) -> bool`

### Poseidon hash function

Refer to the [specification on Poseidon](./poseidon.md). We make use of the following functions from that specification:

- `Poseidon.init(params) -> FqSponge`
- `Poseidon.update(field_elem)`
- `Poseidon.finalize() -> FieldElem`

specify the following functions on top:

- `Poseidon.produce_challenge()` (TODO: uses the endomorphism)
- `Poseidon.to_fr_sponge() -> state_of_fq_sponge_before_eval, FrSponge`

With the current parameters:

* `SPONGE_BOX = 7`
* TODO: round constants?
* TODO: MDS?

### Pasta

Kimchi is made to work on cycles of curves, so the protocol switch between two fields Fq and Fr, where Fq represents the base field and Fr represents the scalar field.

See the [Pasta curves specification](./pasta.md).

## Constraints

TODO: use expr to define the index columns?

### Permutation

{sections.permutation}

### Lookup

{sections.lookup}

### Gates

#### Double Generic Gate

{sections.generic}

#### Poseidon

{sections.poseidon}

#### Chacha 

{sections.chacha}

#### Elliptic Curve Addition

{sections.complete_add}

#### Endo Scalar

{sections.endomul_scalar}

#### Endo Scalar Multiplication

{sections.endosclmul}

#### Scalar Multiplication 

{sections.varbasemul}

## Constraint System Creation

{sections.constraint_system}

## Prover and Verifier Index Creation

{sections.indexes}

## Proof Data Structure

A proof consists of:

* TKTK

## Proof Creation

{sections.prover}

## Proof Verification

In this section we specify a verifier that batch verify a number of proofs for unrelated circuits.

The verifier expects a list of proofs, where each proof comes with:

* a verifier index
* the actual proof (as specified in the [proof creation section](#proof-creation))
* a vector of commitments ???

The verifier then follows the following steps to verify the proofs. 
Note that a single invalid proofs will invalidate the whole list of proofs. 
If the verifier then wants to isolate the invalid proofs, they will have to either verify proofs one by one, or perform a binary search.

{sections.verifier}
