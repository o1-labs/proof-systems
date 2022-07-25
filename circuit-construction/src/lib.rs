#![doc = include_str!("../../README.md")]

/// Definition of possible constants in circuits
pub mod constants;
/// This contains the prover functions, ranging from curves definitions to prover index and proof generation
pub mod prover;
/// This is the actual writer with all of the available functions to set up a circuit and its corresponding constraint system
pub mod writer;

#[cfg(test)]
mod tests;

/// This contains the Kimchi dependencies being used
pub mod prologue {
    pub use super::constants::{fp_constants, fq_constants, Constants};
    pub use super::prover::{generate_prover_index, prove, CoordinateCurve, FpInner};
    pub use super::writer::{Cs, Var};
    pub use ark_ec::{AffineCurve, ProjectiveCurve};
    pub use ark_ff::{FftField, PrimeField, UniformRand};
    pub use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    pub use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
    pub use groupmap::GroupMap;
    pub use kimchi::verifier::verify;
    pub use mina_curves::pasta::{
        fp::Fp,
        pallas::Pallas as PallasAffine,
        vesta::{Vesta as VestaAffine, VestaParameters},
    };
    pub use oracle::{
        constants::*,
        poseidon::{ArithmeticSponge, Sponge},
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    pub use std::sync::Arc;
}
