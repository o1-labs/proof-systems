use crate::interpreters::mips::column::{SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};
use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use poly_commitment::{ipa::OpeningProof, PolyComm};

pub struct WitnessColumns<G, S, const SCRATCH_SIZE: usize, const SCRATCH_SIZE_INVERSE: usize> {
    pub scratch: [G; SCRATCH_SIZE],
    pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<G: KimchiCurve, const SCRATCH_SIZE: usize, const SCRATCH_SIZE_INVERSE: usize>
{
    pub evaluations: WitnessColumns<
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        SCRATCH_SIZE,
        SCRATCH_SIZE_INVERSE,
    >,
}

impl<G: KimchiCurve> ProofInputs<G, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(SCRATCH_SIZE)),
                scratch_inverse: std::array::from_fn(|_| Vec::with_capacity(SCRATCH_SIZE_INVERSE)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
            },
        }
    }
}

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve, const INSTRUCTION_SET_SIZE: usize> {
    pub commitments: WitnessColumns<
        PolyComm<G>,
        [PolyComm<G>; INSTRUCTION_SET_SIZE],
        SCRATCH_SIZE,
        SCRATCH_SIZE_INVERSE,
    >,
    pub zeta_evaluations: WitnessColumns<
        G::ScalarField,
        [G::ScalarField; INSTRUCTION_SET_SIZE],
        SCRATCH_SIZE,
        SCRATCH_SIZE_INVERSE,
    >,
    pub zeta_omega_evaluations: WitnessColumns<
        G::ScalarField,
        [G::ScalarField; INSTRUCTION_SET_SIZE],
        SCRATCH_SIZE,
        SCRATCH_SIZE_INVERSE,
    >,
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
