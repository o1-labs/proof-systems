use ark_ff::Zero;
use core::{
    fmt::{Display, Formatter, Result},
    ops::Index,
};
use kimchi::circuits::expr::AlphaChallengeTerm;
use serde::{Deserialize, Serialize};
use strum::EnumCount;
use strum_macros::EnumCount as EnumCountMacro;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumCountMacro)]
pub enum ChallengeTerm {
    /// Used to aggregate the constraints describing the relation. It is used to
    /// enforce all constraints are satisfied at the same time.
    /// Often noted `α`.
    ConstraintRandomiser,
    /// Both challenges used in the permutation argument
    Beta,
    Gamma,
    /// Used to homogenize the constraints and allow the protocol to fold two
    /// instances of the same relation into a new one.
    /// Often noted `u` in the paper mentioning "folding protocols".
    ConstraintHomogeniser,
    /// Used by the accumulation protocol (folding) to perform a random linear
    /// transformation of the witnesses and the public values.
    /// Often noted `r` in the paper mentioning "folding protocols".
    RelationRandomiser,
}

impl Display for ChallengeTerm {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ChallengeTerm::ConstraintRandomiser => write!(f, "alpha"),
            ChallengeTerm::Beta => write!(f, "beta"),
            ChallengeTerm::Gamma => write!(f, "gamma"),
            ChallengeTerm::ConstraintHomogeniser => write!(f, "u"),
            ChallengeTerm::RelationRandomiser => write!(f, "r"),
        }
    }
}

pub struct Challenges<F> {
    /// Used to aggregate the constraints describing the relation. It is used to
    /// enforce all constraints are satisfied at the same time.
    /// Often noted `α`.
    pub constraint_randomiser: F,

    /// Both challenges used in the permutation argument.
    pub beta: F,
    pub gamma: F,

    /// Used to homogenize the constraints and allow the protocol to fold two
    /// instances of the same relation into a new one.
    /// Often noted `u` in the paper mentioning "folding protocols".
    pub constraint_homogeniser: F,

    /// Used by the accumulation protocol (folding) to perform a random linear
    /// transformation of the witnesses and the public values.
    /// Often noted `r` in the paper mentioning "folding protocols".
    pub relation_randomiser: F,
}

impl<F> Index<usize> for Challenges<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        if index == 0 {
            &self.constraint_randomiser
        } else if index == 1 {
            &self.beta
        } else if index == 2 {
            &self.gamma
        } else if index == 3 {
            &self.constraint_homogeniser
        } else if index == 4 {
            &self.relation_randomiser
        } else {
            panic!(
                "Index out of bounds, only {} are defined",
                ChallengeTerm::COUNT
            )
        }
    }
}

impl<F: Zero> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            constraint_randomiser: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            constraint_homogeniser: F::zero(),
            relation_randomiser: F::zero(),
        }
    }
}

impl<F> Index<ChallengeTerm> for Challenges<F> {
    type Output = F;

    fn index(&self, term: ChallengeTerm) -> &Self::Output {
        match term {
            ChallengeTerm::ConstraintRandomiser => &self.constraint_randomiser,
            ChallengeTerm::Beta => &self.beta,
            ChallengeTerm::Gamma => &self.gamma,
            ChallengeTerm::ConstraintHomogeniser => &self.constraint_homogeniser,
            ChallengeTerm::RelationRandomiser => &self.relation_randomiser,
        }
    }
}

impl<'a> AlphaChallengeTerm<'a> for ChallengeTerm {
    const ALPHA: Self = Self::ConstraintRandomiser;
}
