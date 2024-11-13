use std::collections::BTreeMap;

use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use kimchi_msm::{
    logup::{prover::Env as LookupEnv, LookupProof},
    LogupWitness, LookupTableID,
};
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::SCRATCH_SIZE};

#[derive(Clone)]
pub struct WitnessColumns<F, G: KimchiCurve, S, ID: LookupTableID> {
    pub scratch: [F; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: F,
    pub error: F,
    pub selector: S,
    pub lookup_env: Option<LookupEnv<G, ID>>,
}

pub struct ProofInputs<G: KimchiCurve, ID: LookupTableID> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, G, Vec<G::ScalarField>, ID>,
    pub logups: BTreeMap<ID, LogupWitness<G::ScalarField, ID>>,
}

impl<G: KimchiCurve, ID: LookupTableID> ProofInputs<G, ID> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
                lookup_env: None,
            },
            logups: BTreeMap::new(),
        }
    }
}

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve, ID: LookupTableID> {
    pub commitments: WitnessColumns<PolyComm<G>, G, [PolyComm<G>; N_MIPS_SEL_COLS], ID>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, G, [G::ScalarField; N_MIPS_SEL_COLS], ID>,
    pub zeta_omega_evaluations:
        WitnessColumns<G::ScalarField, G, [G::ScalarField; N_MIPS_SEL_COLS], ID>,
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    pub logup_commitments: Option<LookupProof<PolyComm<G>, ID>>,
    pub logup_evaluations: Option<LookupProof<PointEvaluations<G::ScalarField>, ID>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
