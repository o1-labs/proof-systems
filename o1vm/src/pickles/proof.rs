use kimchi::curve::KimchiCurve;
use poly_commitment::{ipa::OpeningProof, PolyComm};

pub struct WitnessColumns<G> {
    pub scratch: [G; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: G,
}

pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>>,
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
    pub commitments: WitnessColumns<PolyComm<G>>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
