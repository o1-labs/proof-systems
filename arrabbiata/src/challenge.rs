use ark_ff::Zero;
use core::{
    fmt::{Display, Formatter, Result},
    ops::{Index, IndexMut},
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
    ConstraintCombiner,
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
    RelationCombiner,
}

impl Display for ChallengeTerm {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ChallengeTerm::ConstraintCombiner => write!(f, "alpha"),
            ChallengeTerm::Beta => write!(f, "beta"),
            ChallengeTerm::Gamma => write!(f, "gamma"),
            ChallengeTerm::ConstraintHomogeniser => write!(f, "u"),
            ChallengeTerm::RelationCombiner => write!(f, "r"),
        }
    }
}

pub struct Challenges<F> {
    /// Used to aggregate the constraints describing the relation. It is used to
    /// enforce all constraints are satisfied at the same time.
    /// Often noted `α`.
    pub constraint_combiner: F,

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
    pub relation_combiner: F,
}

impl<F> Index<usize> for Challenges<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        if index == 0 {
            &self.constraint_combiner
        } else if index == 1 {
            &self.beta
        } else if index == 2 {
            &self.gamma
        } else if index == 3 {
            &self.constraint_homogeniser
        } else if index == 4 {
            &self.relation_combiner
        } else {
            panic!(
                "Index out of bounds, only {} are defined",
                ChallengeTerm::COUNT
            )
        }
    }
}

impl<F> IndexMut<usize> for Challenges<F> {
    fn index_mut(&mut self, index: usize) -> &mut F {
        if index == 0 {
            &mut self.constraint_combiner
        } else if index == 1 {
            &mut self.beta
        } else if index == 2 {
            &mut self.gamma
        } else if index == 3 {
            &mut self.constraint_homogeniser
        } else if index == 4 {
            &mut self.relation_combiner
        } else {
            panic!(
                "Index out of bounds, only {} are defined",
                ChallengeTerm::COUNT
            )
        }
    }
}

impl<F> IndexMut<ChallengeTerm> for Challenges<F> {
    fn index_mut(&mut self, term: ChallengeTerm) -> &mut F {
        match term {
            ChallengeTerm::ConstraintCombiner => &mut self.constraint_combiner,
            ChallengeTerm::Beta => &mut self.beta,
            ChallengeTerm::Gamma => &mut self.gamma,
            ChallengeTerm::ConstraintHomogeniser => &mut self.constraint_homogeniser,
            ChallengeTerm::RelationCombiner => &mut self.relation_combiner,
        }
    }
}

impl<F: Zero> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            constraint_combiner: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            constraint_homogeniser: F::zero(),
            relation_combiner: F::zero(),
        }
    }
}

impl<F> Index<ChallengeTerm> for Challenges<F> {
    type Output = F;

    fn index(&self, term: ChallengeTerm) -> &Self::Output {
        match term {
            ChallengeTerm::ConstraintCombiner => &self.constraint_combiner,
            ChallengeTerm::Beta => &self.beta,
            ChallengeTerm::Gamma => &self.gamma,
            ChallengeTerm::ConstraintHomogeniser => &self.constraint_homogeniser,
            ChallengeTerm::RelationCombiner => &self.relation_combiner,
        }
    }
}

impl AlphaChallengeTerm<'_> for ChallengeTerm {
    const ALPHA: Self = Self::ConstraintCombiner;
}
