use crate::{
    lookups::{LookupTableIDs, LookupWitness},
    mvlookup::{LookupProof, LookupTableID},
    witness::Witness,
    MVLookupWitness,
};

use ark_ff::UniformRand;
use rand::thread_rng;

use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{ColumnEvaluations, ExprError};
use kimchi::curve::KimchiCurve;
use kimchi::proof::PointEvaluations;
use poly_commitment::{commitment::PolyComm, OpenProof};

#[derive(Debug)]
pub struct ProofInputs<const N: usize, G: KimchiCurve, ID: LookupTableID> {
    /// Actual values w_i of the witness columns. "Evaluations" as in
    /// evaluations of polynomial P_w that interpolates w_i.
    pub evaluations: Witness<N, Vec<G::ScalarField>>,
    pub mvlookups: Vec<MVLookupWitness<G::ScalarField, ID>>,
    // TODO Unless we use ZK rows, this is unused by the prover, since
    // public inputs are modelled as a prefix of the witness that is
    // committed w/o blinders.
    /// The number of public inputs. It is supposed that the first
    /// `public_input_size` columns of the witness represent the public values
    pub public_input_size: usize,
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
            public_input_size: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofEvaluations<const N: usize, F> {
    /// Witness evaluations, including public input
    pub(crate) witness_evals: Witness<N, PointEvaluations<F>>,
    /// MVLookup argument evaluations
    pub(crate) mvlookup_evals: Option<LookupProof<PointEvaluations<F>>>,
    /// Evaluation of Z_H(xi) (t_0(X) + xi^n t_1(X) + ...) at xi.
    pub(crate) ft_eval1: F,
}

impl<const N: usize, F: Clone> ColumnEvaluations<F> for ProofEvaluations<N, F> {
    type Column = crate::columns::Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        let crate::columns::Column::X(i) = col else {
            todo!()
        };
        if i < self.witness_evals.cols.len() {
            Ok(self.witness_evals.cols[i].clone())
        } else {
            panic!("No such column index")
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofCommitments<const N: usize, G: KimchiCurve> {
    /// Commitments to the N columns of the circuits, also called the 'witnesses'.
    /// If some columns are considered as public inputs, it is counted in the witness.
    pub(crate) witness_comms: Witness<N, PolyComm<G>>,
    /// Commitments to the polynomials used by the lookup argument.
    /// The values contains the chunked polynomials.
    pub(crate) mvlookup_comms: Option<LookupProof<PolyComm<G>>>,
    /// Commitments to the quotient polynomial.
    /// The value contains the chunked polynomials.
    pub(crate) t_comm: PolyComm<G>,
}

#[derive(Debug, Clone)]
pub struct Proof<const N: usize, G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub(crate) proof_comms: ProofCommitments<N, G>,
    pub(crate) proof_evals: ProofEvaluations<N, G::ScalarField>,
    pub(crate) opening_proof: OpeningProof,
}
