use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use num_bigint::BigUint;
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::column::{N_MIPS_SEL_COLS, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; SCRATCH_SIZE],
    pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs {
    pub evaluations: WitnessColumns<Vec<BigUint>, Vec<BigUint>>,
}

impl ProofInputs {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                scratch_inverse: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
            },
        }
    }
}

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve> {
    pub commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
