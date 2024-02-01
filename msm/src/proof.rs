use ark_ff::Zero;
use kimchi::curve::KimchiCurve;
use poly_commitment::{commitment::PolyComm, OpenProof};

use crate::{DOMAIN_SIZE, NUM_LIMBS};

// Compute a + b = q * p + c
// p being the scalar field of Pallas
#[derive(Debug)]
pub struct WitnessColumns<G> {
    pub a: [G; NUM_LIMBS],
    pub b: [G; NUM_LIMBS],
    pub c: [G; NUM_LIMBS],
    // pub q: G,
}

#[derive(Debug)]
pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for ProofInputs<G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                a: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                b: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                c: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                // q: G::ScalarField::zero(),
            },
        }
    }
}

#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub commitments: WitnessColumns<PolyComm<G>>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    pub opening_proof: OpeningProof,
}
