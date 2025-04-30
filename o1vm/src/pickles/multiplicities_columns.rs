//TODO rename
use crate::lookups::{LookupTableIDs, *};
use ark_ff::{FftField, Field, PrimeField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use core::ops::Index;
use kimchi::{
    circuits::{
        domains::{Domain, EvaluationDomains},
        expr::{
            unnormalized_lagrange_basis, AlphaChallengeTerm, ColumnEnvironment, ColumnEvaluations,
            ConstantExpr, ConstantTerm::Literal, Constants, Expr, ExprError, ExprInner, RowOffset,
            Variable,
        },
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
    proof::PointEvaluations,
};
use poly_commitment::{ipa::OpeningProof, PolyComm};
use serde::{Deserialize, Serialize};
use std::iter::Chain;

// This file contains the associated types and methods for the multiplicities prover.
// It defines the columns, the proof, proof input, and constraint expressions.

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum MultiplicitiesColumns {
    FixedLookup(LookupTableIDs, usize),
    Multiplicities(LookupTableIDs),
    Inverses(LookupTableIDs),
    Acc,
}
#[derive(Clone)]
pub struct ColumnEnv<X> {
    pub fixedlookup: FixedLookup<Vec<X>>,
    pub multiplicities: FixedLookup<X>,
    pub inverses: FixedLookup<X>,
    pub acc: X,
}

impl<X> IntoIterator for ColumnEnv<X> {
    type Item = X;
    type IntoIter = std::vec::IntoIter<X>;
    fn into_iter(self) -> Self::IntoIter {
        let ColumnEnv {
            fixedlookup,
            multiplicities,
            inverses,
            acc,
        } = self;
        let mut vec = vec![];
        fixedlookup.into_iter().for_each(|x| vec.extend(x));
        multiplicities.into_iter().for_each(|x| vec.push(x));
        inverses.into_iter().for_each(|x| vec.push(x));
        vec.push(acc);
        vec.into_iter()
    }
}

impl<X> ColumnEnv<X> {
    pub fn map<Y, F>(self, mut f: F) -> ColumnEnv<Y>
    where
        F: FnMut(X) -> Y,
        Self: Sized,
    {
        let ColumnEnv {
            fixedlookup,
            multiplicities,
            inverses,
            acc,
        } = self;

        ColumnEnv {
            fixedlookup: fixedlookup.map(|vec| vec.into_iter().map(&mut f).collect()),
            inverses: inverses.map(&mut f),
            acc: f(acc),
            multiplicities: multiplicities.map(&mut f),
        }
    }
}

pub struct MultiplicitiesProofInput<G: KimchiCurve> {
    pub fixedlookup: FixedLookup<Vec<Vec<G::ScalarField>>>,
    pub fixedlookup_transposed: FixedLookup<Vec<Vec<G::ScalarField>>>,
    pub multiplicities: FixedLookup<Vec<G::ScalarField>>,
    pub fixedlookupcommitment: FixedLookup<Vec<PolyComm<G>>>,
    pub beta_challenge: G::ScalarField,
    pub gamma_challenge: G::ScalarField,
}
#[derive(Clone)]
pub struct AllColumns<X> {
    pub cols: ColumnEnv<X>,
    pub quotient_chunks: Vec<X>,
}

impl<X> IntoIterator for AllColumns<X> {
    type Item = X;
    type IntoIter =
        Chain<<ColumnEnv<X> as IntoIterator>::IntoIter, <Vec<X> as IntoIterator>::IntoIter>;
    fn into_iter(self) -> Self::IntoIter {
        let AllColumns {
            cols,
            quotient_chunks,
        } = self;
        cols.into_iter().chain(quotient_chunks)
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
        let Eval { zeta, zeta_omega } = self;
        zeta.into_iter().chain(zeta_omega)
    }
}

pub struct Proof<G: KimchiCurve> {
    pub commitments: AllColumns<G>,
    pub evaluations: Eval<G::ScalarField>,
    pub ipa_proof: OpeningProof<G>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiplicitiesChallengeTerm {
    /// The challenge to compute 1/(beta + lookupvalue)
    Beta,
    /// The challenge to combine tuple sum gamma^i lookupvalue_i
    Gamma,
    /// Constraint combiner challenge
    Alpha,
}

pub struct MultiplicitiesChallenges<F> {
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
}

impl<F: Field> Index<MultiplicitiesChallengeTerm> for MultiplicitiesChallenges<F> {
    type Output = F;

    fn index(&self, term: MultiplicitiesChallengeTerm) -> &Self::Output {
        let MultiplicitiesChallenges { alpha, beta, gamma } = self;
        match term {
            MultiplicitiesChallengeTerm::Alpha => alpha,
            MultiplicitiesChallengeTerm::Beta => beta,
            MultiplicitiesChallengeTerm::Gamma => gamma,
        }
    }
}

impl std::fmt::Display for MultiplicitiesChallengeTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use MultiplicitiesChallengeTerm::*;
        let str = match self {
            Alpha => "alpha".to_string(),
            Beta => "beta".to_string(),
            Gamma => "gamma".to_string(),
        };
        write!(f, "{}", str)
    }
}

// alpha doesn't exists here
impl<'a> AlphaChallengeTerm<'a> for MultiplicitiesChallengeTerm {
    const ALPHA: Self = MultiplicitiesChallengeTerm::Alpha;
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
/// All are evaluations.
pub struct MultiplicitiesEvalEnvironment<'a, F: FftField> {
    pub columns: &'a ColumnEnv<Evaluations<F, Radix2EvaluationDomain<F>>>,
    pub challenges: MultiplicitiesChallenges<F>,
    pub constants: Constants<F>,
    pub domain: &'a EvaluationDomains<F>,
    pub l0_1: F,
}

// Necessarry trait to evaluate the numerator of T in the prover
impl<'a, F: FftField>
    ColumnEnvironment<'a, F, MultiplicitiesChallengeTerm, MultiplicitiesChallenges<F>>
    for MultiplicitiesEvalEnvironment<'a, F>
{
    type Column = MultiplicitiesColumns;

    fn get_column(
        &self,
        col: &Self::Column,
    ) -> Option<&'a Evaluations<F, Radix2EvaluationDomain<F>>> {
        use MultiplicitiesColumns::*;
        let MultiplicitiesEvalEnvironment {
            columns:
                ColumnEnv {
                    fixedlookup,
                    multiplicities,
                    inverses,
                    acc,
                },
            challenges: _,
            constants: _,
            domain: _,
            l0_1: _,
        } = self;
        match col {
            // Improve me: I could not use the [] syntax for indexing
            FixedLookup(id, i) => Some(&fixedlookup[*id][*i]),
            Multiplicities(id) => Some(&multiplicities[*id]),
            Inverses(id) => Some(&inverses[*id]),
            Acc => Some(acc),
        }
    }

    fn get_domain(&self, d: Domain) -> Radix2EvaluationDomain<F> {
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
        &self.constants
    }

    fn get_challenges(&self) -> &MultiplicitiesChallenges<F> {
        &self.challenges
    }

    fn vanishes_on_zero_knowledge_and_previous_rows(
        &self,
    ) -> &'a Evaluations<F, Radix2EvaluationDomain<F>> {
        panic!("no zk is supposed to be used in this protocol")
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}

// helper to implement the next trait
impl<F> ColumnEnv<F> {
    pub fn get_column(&self, col: &MultiplicitiesColumns) -> Option<&F> {
        let ColumnEnv {
            fixedlookup,
            inverses,
            acc,
            multiplicities,
        } = self;
        match *col {
            MultiplicitiesColumns::FixedLookup(id, i) => Some(&fixedlookup[id][i]),
            MultiplicitiesColumns::Inverses(id) => Some(&inverses[id]),
            MultiplicitiesColumns::Acc => Some(acc),
            MultiplicitiesColumns::Multiplicities(id) => Some(&multiplicities[id]),
        }
    }
}
// Necessarry trait to evaluate the numerator of T at zeta in the verifier
impl<F: PrimeField> ColumnEvaluations<F> for Eval<F> {
    type Column = MultiplicitiesColumns;
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

///////
// Constraint of the multiplicities protocol.
// They are not in the interpreter as they do not depend on the execution trace.
///////

pub type EMultiplicities<F> =
    Expr<ConstantExpr<F, MultiplicitiesChallengeTerm>, MultiplicitiesColumns>;

fn variable<F: Field>(col: MultiplicitiesColumns) -> EMultiplicities<F> {
    EMultiplicities::<F>::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Curr,
    }))
}

fn inverses_constraint<F: PrimeField>() -> Vec<EMultiplicities<F>> {
    let beta: EMultiplicities<F> = MultiplicitiesChallengeTerm::Beta.into();
    let gamma: EMultiplicities<F> = MultiplicitiesChallengeTerm::Gamma.into();

    let mut res = vec![];
    for id in LookupTableIDs::get_fixed_ids().into_iter() {
        let n = id.arity();
        let mut cst: kimchi::circuits::expr::Operations<
            ExprInner<
                kimchi::circuits::expr::Operations<
                    kimchi::circuits::expr::ConstantExprInner<F, MultiplicitiesChallengeTerm>,
                >,
                MultiplicitiesColumns,
            >,
        > = EMultiplicities::<F>::zero();
        for i in 0..n {
            cst *= gamma.clone();
            cst += variable(MultiplicitiesColumns::FixedLookup(id, n - 1 - i));
        }
        cst += beta.clone();
        cst *= variable(MultiplicitiesColumns::Inverses(id));
        cst = cst - variable(MultiplicitiesColumns::Multiplicities(id));
        res.push(cst)
    }

    res
}

pub fn get_multiplicities_constraints<F: PrimeField>(
    domain: &Radix2EvaluationDomain<F>,
    acc_init: F,
    acc_final: F,
) -> Vec<EMultiplicities<F>> {
    // Constraint the inverse wires
    let mut res = inverses_constraint();

    // Recursive constraint of the accumulator
    let partial_acc_recursion = {
        let mut sum_inverses = EMultiplicities::<F>::zero();
        for id in LookupTableIDs::get_fixed_ids() {
            sum_inverses += variable(MultiplicitiesColumns::Inverses(id));
        }
        EMultiplicities::<F>::Atom(ExprInner::Cell(Variable {
            col: MultiplicitiesColumns::Acc,
            row: CurrOrNext::Next,
        })) - variable(MultiplicitiesColumns::Acc)
            - sum_inverses
    };
    // used to not constrain on the n-1 point of the domain
    let unnormalized_l_n_n: EMultiplicities<F> = {
        let field_elt = unnormalized_lagrange_basis::<F>(
            domain,
            (domain.size - 1).try_into().unwrap(),
            &F::pow(&domain.group_gen, [(domain.size - 1)]),
        );
        Literal(field_elt).into()
    };
    let acc_recursion = (unnormalized_l_n_n.clone()
        - EMultiplicities::Atom(ExprInner::UnnormalizedLagrangeBasis(RowOffset {
            zk_rows: false,
            offset: (domain.size - 1).try_into().unwrap(),
        })))
        * partial_acc_recursion;

    // Constrain the initial value of the accumulator
    let acc_init = (EMultiplicities::Atom(ExprInner::UnnormalizedLagrangeBasis(RowOffset {
        zk_rows: false,
        offset: 0,
    }))) * (variable(MultiplicitiesColumns::Acc) - (Literal(acc_init).into()));

    // Constrain the final value of the accumulator
    let acc_final = (EMultiplicities::Atom(ExprInner::UnnormalizedLagrangeBasis(RowOffset {
        zk_rows: false,
        offset: (domain.size - 1).try_into().unwrap(),
    }))) * (variable(MultiplicitiesColumns::Acc) - (Literal(acc_final).into()));

    res.push(acc_recursion);
    res.push(acc_init);
    res.push(acc_final);
    res
}
