use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use core::{iter::Once, ops::Index};
use kimchi::{
    circuits::{
        domains::{Domain, EvaluationDomains},
        expr::{
            AlphaChallengeTerm, ColumnEnvironment, ColumnEvaluations, ConstantExpr, Constants,
            Expr, ExprError,
        },
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
    proof::PointEvaluations,
};
use poly_commitment::ipa::OpeningProof;
use serde::{Deserialize, Serialize};
use std::iter::Chain;

// This file contains the associated types and methods for the lookup prover.
// It defines the columns, the proof, proof input, and constraint expressions.

#[derive(Clone, PartialEq, Copy)]
pub enum LookupColumns {
    Wires(usize),
    Inverses(usize),
    Acc,
}
#[derive(Clone)]
pub struct ColumnEnv<X> {
    pub wires: Vec<X>,
    pub inverses: Vec<X>,
    pub acc: X,
}

impl<X> IntoIterator for ColumnEnv<X> {
    type Item = X;
    type IntoIter = Chain<
        Chain<<Vec<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>,
        <Once<X> as IntoIterator>::IntoIter,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.wires
            .into_iter()
            .chain(self.inverses)
            .chain(std::iter::once(self.acc))
    }
}
// TODO: I could not find a more elegant solution to map over this struct
impl<X> ColumnEnv<X> {
    pub fn my_map<Y, F>(self, f: F) -> ColumnEnv<Y>
    where
        F: FnMut(X) -> Y,
        Self: Sized,
    {
        let nb_wires = self.wires.len();
        let nb_inverses = self.inverses.len();
        let mut iterator = self.into_iter().map(f);
        let mut new_wires = vec![];
        let mut new_inverses = vec![];
        for _ in 0..nb_wires {
            new_wires.push(iterator.next().unwrap());
        }
        for _ in 0..nb_inverses {
            new_inverses.push(iterator.next().unwrap());
        }
        let new_acc = iterator.next().unwrap();
        assert!(iterator.next().is_none());
        ColumnEnv {
            wires: new_wires,
            inverses: new_inverses,
            acc: new_acc,
        }
    }
}

pub struct LookupProofInput<F: PrimeField> {
    pub wires: Vec<Vec<F>>,
    pub arity: Vec<Vec<usize>>,
    pub beta_challenge: F,
    pub gamma_challenge: F,
}
#[derive(Clone)]
pub struct AllColumns<X> {
    pub cols: ColumnEnv<X>,
    pub t_shares: Vec<X>,
}

impl<X> IntoIterator for AllColumns<X> {
    type Item = X;
    type IntoIter =
        Chain<<ColumnEnv<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>;
    fn into_iter(self) -> Self::IntoIter {
        self.cols.into_iter().chain(self.t_shares)
    }
}

#[derive(Clone)]
pub struct Eval<F: PrimeField> {
    pub zeta: AllColumns<F>,
    pub zeta_omega: AllColumns<F>,
}

impl<F: PrimeField> IntoIterator for Eval<F> {
    type Item = F;
    type IntoIter =
        Chain<<AllColumns<F> as IntoIterator>::IntoIter, <AllColumns<F> as IntoIterator>::IntoIter>;
    fn into_iter(self) -> Self::IntoIter {
        self.zeta.into_iter().chain(self.zeta_omega)
    }
}

pub struct Proof<G: KimchiCurve> {
    pub commitments: AllColumns<G>,
    pub evaluations: Eval<G::ScalarField>,
    pub ipa_proof: OpeningProof<G>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LookupChallengeTerm {
    //The challenge to compute 1/(beta + lookupvalue)
    Beta,
    // The challenge to combine tuple sum beta^i lookupvalue_i
    Gamma,
    // The challenge to combine constraints
    Alpha,
}

pub struct LookupChallenges<F> {
    pub beta: F,
    pub gamma: F,
    pub alpha: F,
}

impl<F: Field> Index<LookupChallengeTerm> for LookupChallenges<F> {
    type Output = F;

    fn index(&self, term: LookupChallengeTerm) -> &Self::Output {
        match term {
            LookupChallengeTerm::Alpha => &self.alpha,
            LookupChallengeTerm::Beta => &self.beta,
            LookupChallengeTerm::Gamma => &self.gamma,
        }
    }
}

impl std::fmt::Display for LookupChallengeTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use LookupChallengeTerm::*;
        let str = match self {
            Alpha => "alpha".to_string(),
            Beta => "beta".to_string(),
            Gamma => "gamma".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl<'a> AlphaChallengeTerm<'a> for LookupChallengeTerm {
    const ALPHA: Self = Self::Alpha;
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
/// All are evaluations.
pub struct LookupEvalEnvironment<'a, F: FftField> {
    pub columns: &'a ColumnEnv<Evaluations<F, D<F>>>,
    pub challenges: LookupChallenges<F>,
    pub domain: &'a EvaluationDomains<F>,
    pub l0_1: F,
}

// Necessary trait to evaluate the numerator of T in the prover
impl<'a, F: FftField> ColumnEnvironment<'a, F, LookupChallengeTerm, LookupChallenges<F>>
    for LookupEvalEnvironment<'a, F>
{
    type Column = LookupColumns;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evaluations<F, D<F>>> {
        use LookupColumns::*;
        match col {
            Wires(i) => Some(&self.columns.wires[*i]),
            Inverses(i) => Some(&self.columns.inverses[*i]),
            Acc => Some(&self.columns.acc),
        }
    }

    fn get_domain(&self, d: Domain) -> D<F> {
        match d {
            Domain::D1 => self.domain.d1,
            Domain::D2 => self.domain.d2,
            Domain::D4 => self.domain.d4,
            Domain::D8 => self.domain.d8,
        }
    }
    // TODO verify this
    fn column_domain(&self, _col: &Self::Column) -> Domain {
        Domain::D8
    }
    // We do not have constants here
    fn get_constants(&self) -> &Constants<F> {
        panic!("no constants are supposed to be used in this protocol")
    }

    fn get_challenges(&self) -> &LookupChallenges<F> {
        &self.challenges
    }

    fn vanishes_on_zero_knowledge_and_previous_rows(&self) -> &'a Evaluations<F, D<F>> {
        panic!("no zk is supposed to be used in this protocol")
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}

// helper to implement the next trait
impl<F> ColumnEnv<F> {
    pub fn get_column(&self, col: &LookupColumns) -> Option<&F> {
        match *col {
            LookupColumns::Wires(i) => self.wires.get(i),
            LookupColumns::Inverses(i) => self.inverses.get(i),
            LookupColumns::Acc => Some(&self.acc),
        }
    }
}
// Necessary trait to evaluate the numerator of T at zeta in the verifier
impl<F: PrimeField> ColumnEvaluations<F> for Eval<F> {
    type Column = LookupColumns;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        if let Some(&zeta) = self.zeta.cols.get_column(&col) {
            if let Some(&zeta_omega) = self.zeta_omega.cols.get_column(&col) {
                Ok(PointEvaluations { zeta, zeta_omega })
            } else {
                Err(ExprError::MissingEvaluation(col, CurrOrNext::Next))
            }
        } else {
            Err(ExprError::MissingEvaluation(col, CurrOrNext::Curr))
        }
    }
}

pub type ELookup<F> = Expr<ConstantExpr<F, LookupChallengeTerm>, LookupColumns>;
