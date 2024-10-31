use kimchi::curve::KimchiCurve;
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::ToInverseOrNot};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<F: Field> {
    pub evaluations: WitnessColumns<Vec<F>, Vec<F>>,
}

pub struct NotInversedProofInputs<F: Field> {
    pub scratch: [Vec<ToInverseOrNot<F>>; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: Vec<F>,
    pub error: Vec<F>,
    pub selector: Vec<F>,
}

impl<G: KimchiCurve> ProofInputs<G> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
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
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
