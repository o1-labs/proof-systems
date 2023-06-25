pub mod chunked;
mod combine;
pub mod commitment;
pub mod error;
pub mod evaluation_proof;
pub mod srs;

#[cfg(test)]
mod tests;

pub use commitment::PolyComm;

use crate::commitment::CommitmentCurve;
use crate::evaluation_proof::DensePolynomialOrEvaluations;
use ark_ec::AffineCurve;
use ark_poly::EvaluationDomain;
use mina_poseidon::FqSponge;
use rand_core::{CryptoRng, RngCore};

pub trait OpenProof {
    type G: CommitmentCurve;
    type SRS;

    fn open<EFqSponge, RNG, D: EvaluationDomain<<Self::G as AffineCurve>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<Self::G as CommitmentCurve>::Map,
        plnms: &[(
            DensePolynomialOrEvaluations<<Self::G as AffineCurve>::ScalarField, D>,
            Option<usize>,
            PolyComm<<Self::G as AffineCurve>::ScalarField>,
        )], // vector of polynomial with optional degree bound and commitment randomness
        elm: &[<Self::G as AffineCurve>::ScalarField], // vector of evaluation points
        polyscale: <Self::G as AffineCurve>::ScalarField, // scaling factor for polynoms
        evalscale: <Self::G as AffineCurve>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                                // sponge
        rng: &mut RNG,
    ) -> Self
    where
        EFqSponge: Clone
            + FqSponge<
                <Self::G as AffineCurve>::BaseField,
                Self::G,
                <Self::G as AffineCurve>::ScalarField,
            >,
        RNG: RngCore + CryptoRng;
}
