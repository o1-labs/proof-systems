#![doc = include_str!("../../README.md")]

#[macro_use]
extern crate num_derive;

pub use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, GateType},
    polynomials::generic::GenericGateSpec,
    wires::Wire,
};
pub use cairo::{CairoInstruction, CairoMemory, CairoProgram, FlagBits, Offsets, Pointers};
pub use commitment_dlog::{
    commitment::{
        b_poly, b_poly_coefficients, combined_inner_product, BatchEvaluationProof, CommitmentCurve,
        Evaluation, PolyComm,
    },
    evaluation_proof::OpeningProof,
    srs::{endos, SRS},
};
pub use groupmap::{BWParameters, GroupMap};
pub use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
pub use o1_utils::{
    field_helpers, hasher::CryptoDigest, math, types::fields, ExtendedDensePolynomial,
    ExtendedEvaluations,
};
pub use oracle::{
    constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
    pasta::fp_kimchi,
    poseidon::{sbox, ArithmeticSponge, ArithmeticSpongeParams, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge, FqSponge, ScalarChallenge},
};

pub mod alphas;
pub mod bench;
pub mod circuits;
pub mod error;
pub mod linearization;
pub mod plonk_sponge;
pub mod proof;
pub mod prover;
pub mod prover_index;
pub mod verifier;
pub mod verifier_index;

#[cfg(test)]
mod tests;
