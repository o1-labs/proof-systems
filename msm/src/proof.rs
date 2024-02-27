use ark_ff::UniformRand;
use rand::{prelude::*, thread_rng};
use rayon::iter::{FromParallelIterator, IntoParallelIterator, ParallelIterator};

use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{ColumnEvaluations, ExprError};
use kimchi::curve::KimchiCurve;
use kimchi::proof::PointEvaluations;
use poly_commitment::{commitment::PolyComm, OpenProof};

use crate::mvlookup::{LookupProof, LookupWitness};

/// List all columns of the circuit.
/// It is parametrized by a type `T` which can be either:
/// - `Vec<G::ScalarField>` for the evaluations
/// - `PolyComm<G>` for the commitments
#[derive(Debug, Clone)]
pub struct WitnessColumns<T> {
    pub x: Vec<T>,
}

impl<'lt, G> IntoIterator for &'lt WitnessColumns<G> {
    type Item = &'lt G;
    type IntoIter = std::vec::IntoIter<&'lt G>;

    fn into_iter(self) -> Self::IntoIter {
        let n = self.x.len();
        let mut iter_contents = Vec::with_capacity(n);
        iter_contents.extend(&self.x);
        iter_contents.into_iter()
    }
}

impl<G> IntoParallelIterator for WitnessColumns<G>
where
    Vec<G>: IntoParallelIterator,
{
    type Iter = <Vec<G> as IntoParallelIterator>::Iter;
    type Item = <Vec<G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let n = self.x.len();
        let mut iter_contents = Vec::with_capacity(n);
        iter_contents.extend(self.x);
        iter_contents.into_par_iter()
    }
}

impl<G: Send + std::fmt::Debug> FromParallelIterator<G> for WitnessColumns<G> {
    fn from_par_iter<I>(par_iter: I) -> Self
    where
        I: IntoParallelIterator<Item = G>,
    {
        let iter_contents = par_iter.into_par_iter().collect::<Vec<_>>();
        WitnessColumns { x: iter_contents }
    }
}

impl<'data, G> IntoParallelIterator for &'data WitnessColumns<G>
where
    Vec<&'data G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let n = self.x.len();
        let mut iter_contents = Vec::with_capacity(n);
        iter_contents.extend(self.x.iter());
        iter_contents.into_par_iter()
    }
}

impl<'data, G> IntoParallelIterator for &'data mut WitnessColumns<G>
where
    Vec<&'data mut G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data mut G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data mut G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let n = self.x.len();
        let mut iter_contents = Vec::with_capacity(n);
        iter_contents.extend(self.x.iter_mut());
        iter_contents.into_par_iter()
    }
}

#[derive(Debug)]
pub struct Witness<G: KimchiCurve> {
    /// Actual values w_i of the witness columns. "Evaluations" as in
    /// evaluations of polynomial P_w that interpolates w_i.
    pub evaluations: WitnessColumns<Vec<G::ScalarField>>,
    pub mvlookups: Vec<LookupWitness<G::ScalarField>>,
}

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
impl<G: KimchiCurve> Witness<G> {
    pub fn random(domain: EvaluationDomains<G::ScalarField>) -> Self {
        let mut rng = thread_rng();
        let random_n = rng.gen_range(1..1000);
        Witness {
            evaluations: WitnessColumns {
                x: (0..random_n)
                    .map(|_| {
                        (0..domain.d1.size as usize)
                            .map(|_| G::ScalarField::rand(&mut rng))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            },
            mvlookups: vec![LookupWitness::<G::ScalarField>::random(domain)],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofEvaluations<F> {
    /// public input polynomials
    pub(crate) public_evals: Option<PointEvaluations<F>>,
    /// witness polynomials
    pub(crate) witness_evals: WitnessColumns<PointEvaluations<F>>,
    /// MVLookup argument
    pub(crate) mvlookup_evals: Option<LookupProof<PointEvaluations<F>>>,
    /// Evaluation of Z_H(xi) (t_0(X) + xi^n t_1(X) + ...) at xi.
    pub(crate) ft_eval1: F,
}

impl<F: Clone> ColumnEvaluations<F> for ProofEvaluations<F> {
    type Column = crate::columns::Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        let crate::columns::Column::X(i) = col;
        if i < self.witness_evals.x.len() {
            Ok(self.witness_evals.x[i].clone())
        } else {
            panic!("No such column index")
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofCommitments<G: KimchiCurve> {
    pub(crate) witness_comms: WitnessColumns<PolyComm<G>>,
    pub(crate) mvlookup_comms: Option<LookupProof<PolyComm<G>>>,
    pub(crate) t_comm: PolyComm<G>,
}

#[derive(Debug, Clone)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub(crate) proof_comms: ProofCommitments<G>,
    pub(crate) proof_evals: ProofEvaluations<G::ScalarField>,
    pub(crate) opening_proof: OpeningProof,
}
