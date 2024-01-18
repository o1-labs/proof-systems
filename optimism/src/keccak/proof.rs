use super::column::KeccakColumns;
use crate::DOMAIN_SIZE;
use ark_ff::{One, Zero};
use kimchi::curve::KimchiCurve;
use poly_commitment::{OpenProof, PolyComm};

#[derive(Debug)]
pub struct KeccakProofInputs<G: KimchiCurve> {
    _evaluations: KeccakColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for KeccakProofInputs<G> {
    fn default() -> Self {
        KeccakProofInputs {
            _evaluations: KeccakColumns {
                hash_index: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                step_index: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_round: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_absorb: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_squeeze: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_root: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_pad: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flag_length: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                two_to_pad: (0..DOMAIN_SIZE).map(|_| G::ScalarField::one()).collect(),
                inverse_round: (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect(),
                flags_bytes: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                pad_suffix: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                round_constants: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                curr: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                next: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}

#[derive(Debug)]
pub struct KeccakProof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    _commitments: KeccakColumns<PolyComm<G>>,
    _zeta_evaluations: KeccakColumns<G::ScalarField>,
    _zeta_omega_evaluations: KeccakColumns<G::ScalarField>,
    _opening_proof: OpeningProof,
}
