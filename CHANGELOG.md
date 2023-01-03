# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]

### [0.1.0] - 2022-12-19

- **Changed**:
  - `ForeignFieldMul` uses shifted plookups to check 3-bit length of the column 7 of the witness, reducing by 1 the number of constraints and using 1 fewer witness cell.
  - The `Next` row of `ForeignFieldMul` uses 1 fewer witness cell and is moved to the last column of the `Curr` row.
- **Removed**:
  - The high limb carry of the quotient bound in `ForeignFieldMul` is removed because it is always zero. 
- **Security**:
  - The sign of `ForeignFieldAdd` gates is moved to the fourth coefficient, allowing for the copy constraint of the overflow flag from the bound check, reducing the number of constraints by 1, and using 1 fewer witness cell.

### [0.1.0] - 2022-12-14

- **Added**
  - `TestFramework` is used by custom gates.
- **Removed**
  - Custom gates verification functions (which are slower).

### [0.1.0] - 2022-12-13

- **Changed**
  - Foreign field modulus of the gates `ForeignFieldAdd` and `ForeignFieldMul` is configurable through their first 3 coefficients. 

### [0.1.0] - 2022-12-12

- **Added**
  - `Not` gadget for Keccak.

### [0.1.0] - 2022-12-09

- **Added**
  - Enable compact-limb mode for range check gadget by setting the first coefficient of the `RangeCheck1` gate to 1.

### [0.1.0] - 2022-12-08

- **Added**: 
  - `Rot64` gate for Keccak using coefficients to store the rotation offset.
  - `And` gadget for Keccak.
  - Bitwise operations trait for `BigUint`.
- **Changed**: 
  - `ForeignFieldAdd` gate uses two-limb format for the intermediate checks reducing two constraints and one witness cell.
  - `Xor16` admits now `BigUint` inputs instead of `u128`. 
  
### [0.1.0] - 2022-12-06

- **Removed**:
  - The unnecessary field `max_quot_size` in `ProverIndex` and `VerifierIndex` is removed.
  - Irrelevant fields `endo_r` and `endo_q` of the `SRS` struct are removed.

### [0.1.0] - 2022-12-01

- **Added**:
  - The precomputations in the SRS are used to compute chunked representations of Lagrange commitments.
  - `EnabledIf` constructor for `Expr`.
  - `SkipIf` constructor for `PolishToken`.
- **Changed**:
  - Linearization now accepts `Option<FeatureFlags>` in the input, using `EnabledIf` if no features are provided.
- **Fixed**: 
  - On the Mina side, proofs for very small circuits (domain smaller than the SRS) no longer create a shifted segment.

### [0.1.0] - 2022-11-29

- **Fixed**: 
  - Coefficients are evaluated and can be used for custom gates.
- **Removed**:
  - Polynomials are moved out from `ConstraintSystem`.
- **Changed**:
  - All unevaluated selectors now use `selector_polynomial` helper.
- **Added**:
  - `FeatureFlag` structure for optional gates.
  - Prover precomputations are moved into `ProverIndex`.
  - Helper `absorb_commitment` used by the prover and verifier to absorb shifted commitments in `PolyComm`.

### [0.1.0] - 2022-11-27

- **Changed**
  - Occurences of the Horner's method are replaced with the standard implementation in the `arkworks` crate.

### [0.1.0] - 2022-11-25

- **Changed**
  - `Fr_Sponge::absorb_evaluations` have deconstructed `ProofEvaluations`.

### [0.1.0] - 2022-11-16

- **Changed**: 
  - The generic gate is implemented using the `Argument` trait.


### [0.1.0] - 2022-11-14

- **Added**:
  - ASM-like language for debugging.
