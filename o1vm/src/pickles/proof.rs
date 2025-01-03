use crate::interpreters::mips::column::{N_MIPS_SEL_COLS, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};
use ark_ff::Zero;
use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use log::debug;
use poly_commitment::{ipa::OpeningProof, PolyComm};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; SCRATCH_SIZE],
    pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> ProofInputs<G> {
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

    pub fn pad(&mut self) {
        let zero = G::ScalarField::zero();
        let n = self.evaluations.instruction_counter.capacity();
        debug!(
            "Padding proof inputs with zeros, current length {}",
            self.evaluations.instruction_counter.len()
        );
        self.evaluations
            .scratch
            .iter_mut()
            .for_each(|s| s.resize(n, zero));
        self.evaluations
            .scratch_inverse
            .iter_mut()
            .for_each(|s| s.resize(n, zero));
        self.evaluations.instruction_counter.resize(n, zero);
        self.evaluations.error.resize(n, zero);
        self.evaluations.selector.resize(n, zero);
        debug!(
            "Padded proof inputs, now has length {}",
            self.evaluations.instruction_counter.len()
        );
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
