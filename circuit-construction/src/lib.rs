#![doc = include_str!("../../README.md")]

mod constants;
mod prover;
mod writer;

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
        pallas::Affine as PallasAffine,
        vesta::{Affine as VestaAffine, VestaParameters},
    };
    pub use oracle::{
        constants::*,
        poseidon::{ArithmeticSponge, Sponge},
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    pub use std::sync::Arc;
}
