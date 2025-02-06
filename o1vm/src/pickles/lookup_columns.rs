use crate::pickles::lookup_prover::ColumnEnv;
use ark_ff::{FftField, Field};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use core::ops::Index;
use kimchi::circuits::domains::Domain;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::AlphaChallengeTerm;
use kimchi::circuits::expr::ColumnEnvironment;
use kimchi::circuits::expr::Constants;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use serde::{Deserialize, Serialize};

pub enum LookupColumns {
    Wires(usize),
    Inverses(usize),
    Acc,
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
    beta: F,
    gamma: F,
    alpha: F,
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
pub type ELookup<F> = Expr<ConstantExpr<F, LookupChallengeTerm>, LookupColumns>;
