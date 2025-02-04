use ark_ff::Field;
use kimchi::circuits::expr::{AlphaChallengeTerm, CacheId, ConstantExpr, Expr, FormattedOutput};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result},
    ops::Index,
};
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use crate::NUMBER_OF_COLUMNS;

/// This enum represents the different gadgets that can be used in the circuit.
/// The selectors are defined at setup time, can take only the values `0` or
/// `1` and are public.
// IMPROVEME: should we merge it with the Instruction enum?
// It might not be that obvious to do so, as the Instruction enum could be
// defining operations that are not "fixed" in the circuit, but rather
// depend on runtime values (e.g. in a zero-knowledge virtual machine).
#[derive(Debug, Clone, Copy, PartialEq, EnumCountMacro, EnumIter)]
pub enum Gadget {
    App,
    // Elliptic curve related gadgets
    EllipticCurveAddition,
    EllipticCurveScaling,
    /// This gadget implement the Poseidon hash instance described in the
    /// top-level documentation. This implementation does use the "next row"
    /// to allow the computation of one additional round per row. In the current
    /// setup, with [crate::NUMBER_OF_COLUMNS] columns, we can compute 5 full
    /// rounds per row.
    Poseidon,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Column {
    Selector(Gadget),
    PublicInput(usize),
    X(usize),
}

/// Convert a column to a usize. This is used by the library [mvpoly] when we
/// need to compute the cross-terms.
/// For now, only the private inputs and the public inputs are converted,
/// because there might not need to treat the selectors in the polynomial while
/// computing the cross-terms (FIXME: check this later, but pretty sure it's the
/// case).
///
/// Also, the [mvpoly::monomials] implementation of the trait [mvpoly::MVPoly]
/// will be used, and the mapping here is consistent with the one expected by
/// this implementation, i.e. we simply map to an increasing number starting at
/// 0, without any gap.
impl From<Column> for usize {
    fn from(val: Column) -> usize {
        match val {
            Column::X(i) => i,
            Column::PublicInput(i) => NUMBER_OF_COLUMNS + i,
            Column::Selector(_) => unimplemented!("Selectors are not supported. This method is supposed to be called only to compute the cross-term and an optimisation is in progress to avoid the inclusion of the selectors in the multi-variate polynomial."),
        }
    }
}

pub struct Challenges<F: Field> {
    /// Challenge used to aggregate the constraints
    pub alpha: F,

    /// Both challenges used in the permutation argument
    pub beta: F,
    pub gamma: F,

    /// Challenge to homogenize the constraints
    pub homogeneous_challenge: F,

    /// Random coin used to aggregate witnesses while folding
    pub r: F,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeTerm {
    /// Challenge used to aggregate the constraints
    Alpha,
    /// Both challenges used in the permutation argument
    Beta,
    Gamma,
    /// Challenge to homogenize the constraints
    HomogeneousChallenge,
    /// Random coin used to aggregate witnesses while folding
    R,
}

impl Display for ChallengeTerm {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ChallengeTerm::Alpha => write!(f, "alpha"),
            ChallengeTerm::Beta => write!(f, "beta"),
            ChallengeTerm::Gamma => write!(f, "gamma"),
            ChallengeTerm::HomogeneousChallenge => write!(f, "u"),
            ChallengeTerm::R => write!(f, "r"),
        }
    }
}
impl<F: Field> Index<ChallengeTerm> for Challenges<F> {
    type Output = F;

    fn index(&self, term: ChallengeTerm) -> &Self::Output {
        match term {
            ChallengeTerm::Alpha => &self.alpha,
            ChallengeTerm::Beta => &self.beta,
            ChallengeTerm::Gamma => &self.gamma,
            ChallengeTerm::HomogeneousChallenge => &self.homogeneous_challenge,
            ChallengeTerm::R => &self.r,
        }
    }
}

impl<'a> AlphaChallengeTerm<'a> for ChallengeTerm {
    const ALPHA: Self = Self::Alpha;
}

pub type E<Fp> = Expr<ConstantExpr<Fp, ChallengeTerm>, Column>;

// Code to allow for pretty printing of the expressions
impl FormattedOutput for Column {
    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::App => "q_app".to_string(),
                Gadget::EllipticCurveAddition => "q_ec_add".to_string(),
                Gadget::EllipticCurveScaling => "q_ec_mul".to_string(),
                Gadget::Poseidon => "q_pos".to_string(),
            },
            Column::PublicInput(i) => format!("pi_{{{i}}}").to_string(),
            Column::X(i) => format!("x_{{{i}}}").to_string(),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::App => "q_app".to_string(),
                Gadget::EllipticCurveAddition => "q_ec_add".to_string(),
                Gadget::EllipticCurveScaling => "q_ec_mul".to_string(),
                Gadget::Poseidon => "q_pos_next_row".to_string(),
            },
            Column::PublicInput(i) => format!("pi[{i}]"),
            Column::X(i) => format!("x[{i}]"),
        }
    }

    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        // FIXME
        unimplemented!("Not used at the moment")
    }

    fn is_alpha(&self) -> bool {
        // FIXME
        unimplemented!("Not used at the moment")
    }
}
