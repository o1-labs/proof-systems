use ark_ff::Field;
use core::ops::Index;
use kimchi::circuits::expr::AlphaChallengeTerm;
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

pub type ELookup<F> = Expr<ConstantExpr<F, LookupChallengeTerm>, LookupColumns>;
