use std::collections::BTreeMap;

use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use kimchi_msm::{logup::LookupProof, LogupWitness, LookupTableID};
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::column::{N_MIPS_SEL_COLS, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};

#[derive(Clone)]
pub struct Lookup<F> {
    pub m: Vec<F>,
    pub f: Vec<F>,
    pub t: F,
}

#[derive(Clone)]
// TODO : Rename F and S
pub struct WitnessColumns<G: Clone, S, ID: LookupTableID> {
    pub scratch: [G; SCRATCH_SIZE],
    pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
    pub lookup: BTreeMap<ID, Lookup<G>>,
    pub lookup_agg: G,
}

pub struct ProofInputs<G: KimchiCurve, ID: LookupTableID> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>, ID>,
    pub lookups: BTreeMap<ID, LogupWitness<G::ScalarField, ID>>,
}

impl<G: KimchiCurve, ID: LookupTableID> ProofInputs<G, ID> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                scratch_inverse: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
                lookup: BTreeMap::new(),
                lookup_agg: Vec::with_capacity(domain_size),
            },
            lookups: BTreeMap::new(),
        }
    }
}

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve, ID: LookupTableID> {
    pub commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS], ID>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS], ID>,
    pub zeta_omega_evaluations:
        WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS], ID>,
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    pub lookup_commitments: Option<LookupProof<PolyComm<G>, ID>>,
    pub lookup_evaluations: Option<LookupProof<PointEvaluations<G::ScalarField>, ID>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
