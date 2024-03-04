use crate::{
    lookups::{LookupTableIDs, LookupWitness},
    mvlookup::{LookupProof, LookupTableID},
    witness::Witness,
    MVLookupWitness,
};
use ark_ff::UniformRand;
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use poly_commitment::{commitment::PolyComm, OpenProof};
use rand::thread_rng;

#[derive(Debug)]
pub struct ProofInputs<const N: usize, G: KimchiCurve, ID: LookupTableID + Send + Sync + Copy> {
    pub evaluations: Witness<N, Vec<G::ScalarField>>,
    pub mvlookups: Vec<MVLookupWitness<G::ScalarField, ID>>,
}

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
impl<const N: usize, G: KimchiCurve> ProofInputs<N, G, LookupTableIDs> {
    pub fn random(domain: EvaluationDomains<G::ScalarField>) -> Self {
        let mut rng = thread_rng();
        let cols: [Vec<G::ScalarField>; N] = std::array::from_fn(|_| {
            (0..domain.d1.size as usize)
                .map(|_| G::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>()
        });
        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![LookupWitness::<G::ScalarField>::random(domain)],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Proof<const N: usize, G: KimchiCurve, OpeningProof: OpenProof<G>> {
    // Columns/PlonK argument
    pub(crate) commitments: Witness<N, PolyComm<G>>,
    pub(crate) zeta_evaluations: Witness<N, G::ScalarField>,
    pub(crate) zeta_omega_evaluations: Witness<N, G::ScalarField>,
    // MVLookup argument
    pub(crate) mvlookup_commitments: Option<LookupProof<PolyComm<G>>>,
    pub(crate) mvlookup_zeta_evaluations: Option<LookupProof<G::ScalarField>>,
    pub(crate) mvlookup_zeta_omega_evaluations: Option<LookupProof<G::ScalarField>>,
    pub(crate) opening_proof: OpeningProof,
}
