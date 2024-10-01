use kimchi::curve::KimchiCurve;

pub struct WitnessColumns<G> {
    // FIXME: add selectors
    pub scratch: [G; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
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
            },
        }
    }
}
