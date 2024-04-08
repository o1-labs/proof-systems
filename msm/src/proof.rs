use crate::{
    lookups::{LookupTableIDs, LookupWitness},
    mvlookup::{LookupProof, LookupTableID},
    witness::Witness,
    MVLookupWitness,
};

use ark_ff::UniformRand;
use rand::thread_rng;

use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{ColumnEvaluations, ExprError},
    },
    curve::KimchiCurve,
    proof::PointEvaluations,
};
use poly_commitment::{commitment::PolyComm, OpenProof};

#[derive(Debug)]
pub struct ProofInputs<const N: usize, G: KimchiCurve, ID: LookupTableID> {
    /// Actual values w_i of the witness columns. "Evaluations" as in
    /// evaluations of polynomial P_w that interpolates w_i.
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
        let cols: Box<[Vec<G::ScalarField>; N]> = Box::new(std::array::from_fn(|_| {
            (0..domain.d1.size as usize)
                .map(|_| G::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>()
        }));
        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![LookupWitness::<G::ScalarField>::random(domain)],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofEvaluations<const N: usize, F, ID: LookupTableID> {
    /// Witness evaluations, including public inputs
    pub(crate) witness_evals: Witness<N, PointEvaluations<F>>,
    /// MVLookup argument evaluations
    pub(crate) mvlookup_evals: Option<LookupProof<PointEvaluations<F>, ID>>,
    /// Evaluation of Z_H(ζ) (t_0(X) + ζ^n t_1(X) + ...) at ζω.
    pub(crate) ft_eval1: F,
}

/// The trait ColumnEvaluations is used by the verifier.
/// It will return the evaluation of the corresponding column at the
/// evaluation points coined by the verifier during the protocol.
impl<const N: usize, F: Clone, ID: LookupTableID> ColumnEvaluations<F>
    for ProofEvaluations<N, F, ID>
{
    type Column = crate::columns::Column;

    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        let res = match col {
            Self::Column::X(i) => {
                if i < N {
                    self.witness_evals[i].clone()
                } else {
                    panic!("Index out of bounds")
                }
            }
            Self::Column::LookupPartialSum(i) => {
                if let Some(ref lookup) = self.mvlookup_evals {
                    lookup.h[i].clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupAggregation => {
                if let Some(ref lookup) = self.mvlookup_evals {
                    lookup.sum.clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            // FIXME: this requires to have a hashmap for the multiplicities as
            // the index of the column is the table ID
            Self::Column::LookupMultiplicity(i) => {
                if let Some(ref lookup) = self.mvlookup_evals {
                    lookup.m[i as usize].clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            // FIXME: finish implement fixed tables
            // Use hashmap as for the lookup multiplicity
            Self::Column::LookupFixedTable(_) => {
                panic!("Logup is not yet implemented.")
            }
        };
        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct ProofCommitments<const N: usize, G: KimchiCurve, ID: LookupTableID> {
    /// Commitments to the N columns of the circuits, also called the 'witnesses'.
    /// If some columns are considered as public inputs, it is counted in the witness.
    pub(crate) witness_comms: Witness<N, PolyComm<G>>,
    /// Commitments to the polynomials used by the lookup argument.
    /// The values contains the chunked polynomials.
    pub(crate) mvlookup_comms: Option<LookupProof<PolyComm<G>, ID>>,
    /// Commitments to the quotient polynomial.
    /// The value contains the chunked polynomials.
    pub(crate) t_comm: PolyComm<G>,
}

#[derive(Debug, Clone)]
pub struct Proof<const N: usize, G: KimchiCurve, OpeningProof: OpenProof<G>, ID: LookupTableID> {
    pub(crate) proof_comms: ProofCommitments<N, G, ID>,
    pub(crate) proof_evals: ProofEvaluations<N, G::ScalarField, ID>,
    pub(crate) opening_proof: OpeningProof,
}
