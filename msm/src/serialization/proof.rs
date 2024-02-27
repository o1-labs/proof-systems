use crate::{witness::Witness, DOMAIN_SIZE};
use ark_ff::Zero;
use kimchi::curve::KimchiCurve;

/// This struct contains the evaluations of the Witness columns across the whole
/// domain of the circuit
#[derive(Debug)]
pub struct ProofInputs<const N: usize, G: KimchiCurve> {
    #[allow(dead_code)]
    evaluations: Witness<N, Vec<G::ScalarField>>,
}

impl<const N: usize, G: KimchiCurve> Default for ProofInputs<N, G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: Witness {
                cols: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}
