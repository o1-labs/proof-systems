use super::column::KeccakColumns;
use ark_ff::{One, Zero};
use kimchi::curve::KimchiCurve;

#[derive(Debug)]
pub struct KeccakProofInputs<G: KimchiCurve> {
    evaluations: KeccakColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for KeccakProofInputs<G> {
    fn default() -> Self {
        KeccakProofInputs {
            evaluations: KeccakColumns {
                hash_index: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                step_index: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_round: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_absorb: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_squeeze: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_root: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_pad: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flag_length: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                two_to_pad: (0..1 << 15).map(|_| G::ScalarField::one()).collect(),
                inverse_round: (0..1 << 15).map(|_| G::ScalarField::zero()).collect(),
                flags_bytes: std::array::from_fn(|_| {
                    (0..1 << 15).map(|_| G::ScalarField::zero()).collect()
                }),
                pad_suffix: std::array::from_fn(|_| {
                    (0..1 << 15).map(|_| G::ScalarField::zero()).collect()
                }),
                round_constants: std::array::from_fn(|_| {
                    (0..1 << 15).map(|_| G::ScalarField::zero()).collect()
                }),
                curr: std::array::from_fn(|_| {
                    (0..1 << 15).map(|_| G::ScalarField::zero()).collect()
                }),
                next: std::array::from_fn(|_| {
                    (0..1 << 15).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}
