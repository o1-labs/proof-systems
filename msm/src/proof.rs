use crate::{
    logup::{LookupProof, LookupTableID},
    lookups::{LookupTableIDs, LookupWitness},
    witness::Witness,
    LogupWitness, DOMAIN_SIZE,
};
use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{ColumnEvaluations, ExprError},
    },
    curve::KimchiCurve,
    proof::PointEvaluations,
};
use poly_commitment::{commitment::PolyComm, OpenProof};
use rand::thread_rng;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofInputs<const N_WIT: usize, F: PrimeField, ID: LookupTableID> {
    /// Actual values w_i of the witness columns. "Evaluations" as in
    /// evaluations of polynomial P_w that interpolates w_i.
    pub evaluations: Witness<N_WIT, Vec<F>>,
    pub logups: BTreeMap<ID, LogupWitness<F, ID>>,
}

impl<const N_WIT: usize, F: PrimeField> ProofInputs<N_WIT, F, LookupTableIDs> {
    // This should be used only for testing purposes.
    // It is not only in the test API because it is used at the moment in the
    // main.rs. It should be moved to the test API when main.rs is replaced with
    // real production code.
    pub fn random(domain: EvaluationDomains<F>) -> Self {
        let mut rng = thread_rng();
        let cols: Box<[Vec<F>; N_WIT]> = Box::new(std::array::from_fn(|_| {
            (0..domain.d1.size as usize)
                .map(|_| F::rand(&mut rng))
                .collect::<Vec<_>>()
        }));
        let logups = {
            let (table_id, item) = LookupWitness::<F>::random(domain);
            BTreeMap::from([(table_id, item)])
        };
        ProofInputs {
            evaluations: Witness { cols },
            logups,
        }
    }
}

impl<const N_WIT: usize, F: PrimeField, ID: LookupTableID> Default for ProofInputs<N_WIT, F, ID> {
    /// Creates a default proof instance. Note that such an empty "zero" instance will not satisfy any constraint.
    /// E.g. some constraints that have constants inside of them (A - const = 0) cannot be satisfied by it.
    fn default() -> Self {
        ProofInputs {
            evaluations: Witness {
                cols: Box::new(std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| F::zero()).collect()
                })),
            },
            logups: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
// TODO Should public input and fixed selectors evaluations be here?
pub struct ProofEvaluations<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    F,
    ID: LookupTableID,
> {
    /// Witness evaluations, including public inputs
    pub(crate) witness_evals: Witness<N_WIT, PointEvaluations<F>>,
    /// Evaluations of fixed selectors.
    pub(crate) fixed_selectors_evals: Box<[PointEvaluations<F>; N_FSEL]>,
    /// Logup argument evaluations
    pub(crate) logup_evals: Option<LookupProof<PointEvaluations<F>, ID>>,
    /// Evaluation of Z_H(ζ) (t_0(X) + ζ^n t_1(X) + ...) at ζω.
    pub(crate) ft_eval1: F,
}

/// The trait ColumnEvaluations is used by the verifier.
/// It will return the evaluation of the corresponding column at the
/// evaluation points coined by the verifier during the protocol.
impl<
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        F: Clone,
        ID: LookupTableID,
    > ColumnEvaluations<F> for ProofEvaluations<N_WIT, N_REL, N_DSEL, N_FSEL, F, ID>
{
    type Column = crate::columns::Column<usize>;

    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        // TODO: substitute when non-literal generic constants are available
        assert!(N_WIT == N_REL + N_DSEL);
        let res = match col {
            Self::Column::Relation(i) => {
                assert!(i < N_REL, "Index out of bounds");
                self.witness_evals[i].clone()
            }
            Self::Column::DynamicSelector(i) => {
                assert!(i < N_DSEL, "Index out of bounds");
                self.witness_evals[N_REL + i].clone()
            }
            Self::Column::FixedSelector(i) => {
                assert!(i < N_FSEL, "Index out of bounds");
                self.fixed_selectors_evals[i].clone()
            }
            Self::Column::LookupPartialSum((table_id, idx)) => {
                if let Some(ref lookup) = self.logup_evals {
                    lookup.h[&ID::from_u32(table_id)][idx].clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupAggregation => {
                if let Some(ref lookup) = self.logup_evals {
                    lookup.sum.clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupMultiplicity((table_id, idx)) => {
                if let Some(ref lookup) = self.logup_evals {
                    lookup.m[&ID::from_u32(table_id)][idx].clone()
                } else {
                    panic!("No lookup provided")
                }
            }
            Self::Column::LookupFixedTable(table_id) => {
                if let Some(ref lookup) = self.logup_evals {
                    lookup.fixed_tables[&ID::from_u32(table_id)].clone()
                } else {
                    panic!("No lookup provided")
                }
            }
        };
        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct ProofCommitments<const N_WIT: usize, G: KimchiCurve, ID: LookupTableID> {
    /// Commitments to the N columns of the circuits, also called the 'witnesses'.
    /// If some columns are considered as public inputs, it is counted in the witness.
    pub(crate) witness_comms: Witness<N_WIT, PolyComm<G>>,
    /// Commitments to the polynomials used by the lookup argument, coined "logup".
    /// The values contains the chunked polynomials.
    pub(crate) logup_comms: Option<LookupProof<PolyComm<G>, ID>>,
    /// Commitments to the quotient polynomial.
    /// The value contains the chunked polynomials.
    pub(crate) t_comm: PolyComm<G>,
}

#[derive(Debug, Clone)]
pub struct Proof<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    ID: LookupTableID,
> {
    pub(crate) proof_comms: ProofCommitments<N_WIT, G, ID>,
    pub(crate) proof_evals: ProofEvaluations<N_WIT, N_REL, N_DSEL, N_FSEL, G::ScalarField, ID>,
    pub(crate) opening_proof: OpeningProof,
}
