use crate::{challenge::ChallengeTerm, interpreter::Instruction};
use kimchi::circuits::expr::{CacheId, ConstantExpr, Expr, FormattedOutput};
use std::collections::HashMap;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use crate::NUMBER_OF_COLUMNS;

/// This enum represents the different gadgets that can be used in the circuit.
/// The selectors are defined at setup time, can take only the values `0` or
/// `1` and are public.
// IMPROVEME: should we merge it with the Instruction enum?
// It might not be that obvious to do so, as the Instruction enum could be
// defining operations that are not "fixed" in the circuit, but rather
// depend on runtime values (e.g. in a zero-knowledge virtual machine).
#[derive(Debug, Clone, Copy, PartialEq, EnumCountMacro, EnumIter, Eq, Hash)]
pub enum Gadget {
    /// A dummy gadget, doing nothing. Use for padding.
    NoOp,
    /// The gadget defining the application circuit.
    ///
    /// This represents user-defined computation that is composed of
    /// other gadgets via the `StepCircuit` trait.
    App,
    // =========================================================================
    // Arithmetic gadgets
    // =========================================================================
    /// Squaring gadget: x -> x^2
    Squaring,
    /// Cubic polynomial gadget: x -> x^3 + x + 5
    Cubic,
    /// Trivial/identity gadget: x -> x
    Trivial,
    /// Counter gadget: increments a counter
    Counter,
    /// Fibonacci step gadget: (a, b) -> (b, a + b)
    Fibonacci,
    /// MinRoot gadget: computes 5th roots for VDF
    MinRoot,
    // =========================================================================
    // Elliptic curve related gadgets
    // =========================================================================
    EllipticCurveAddition,
    EllipticCurveScaling,
    // =========================================================================
    // Poseidon hash gadgets
    // =========================================================================
    /// The following gadgets implement the Poseidon hash instance described in
    /// the top-level documentation. In the current setup, with
    /// [crate::NUMBER_OF_COLUMNS] columns, we can compute 5 full
    /// rounds per row.
    ///
    /// We split the Poseidon gadget in 13 sub-gadgets, one for each set of 5
    /// full rounds and one for the absorbtion. The parameter is the starting
    /// round of Poseidon. It is expected to be a multiple of five.
    ///
    /// Note that, for now, the gadget can only be used by the verifier circuit.
    PoseidonFullRound(usize),
    /// Absorb [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements into the
    /// sponge. The elements are absorbed into the last
    /// [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements of the permutation
    /// state.
    ///
    /// The values to be absorbed depend on the state of the environment while
    /// executing this instruction.
    ///
    /// Note that, for now, the gadget can only be used by the verifier circuit.
    PoseidonSpongeAbsorb,
    // =========================================================================
    // Poseidon Kimchi (x^7) hash gadgets
    // =========================================================================
    /// Poseidon Kimchi full round gadget (x^7 S-box, 55 rounds total).
    ///
    /// Similar to `PoseidonFullRound` but uses x^7 S-box instead of x^5.
    /// The parameter is the starting round (must be multiple of 5).
    /// With 55 rounds and 5 rounds per row, we have 11 sub-gadgets.
    PoseidonKimchiFullRound(usize),
    // =========================================================================
    // Signature gadgets
    // =========================================================================
    /// Schnorr signature verification gadget.
    ///
    /// Verifies a Schnorr signature compatible with Mina's signature scheme.
    /// Uses Poseidon hash for the challenge and EC scalar multiplication.
    SchnorrVerify,
}

/// Convert an instruction into the corresponding gadget.
impl From<Instruction> for Gadget {
    fn from(val: Instruction) -> Gadget {
        match val {
            Instruction::NoOp => Gadget::NoOp,
            Instruction::PoseidonFullRound(starting_round) => {
                Gadget::PoseidonFullRound(starting_round)
            }
            Instruction::PoseidonSpongeAbsorb => Gadget::PoseidonSpongeAbsorb,
            Instruction::EllipticCurveScaling(_i_comm, _s) => Gadget::EllipticCurveScaling,
            Instruction::EllipticCurveAddition(_i) => Gadget::EllipticCurveAddition,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Column {
    Selector(Gadget),
    PublicInput(usize),
    X(usize),
}

/// Convert a column to a usize. This is used by the library [mvpoly] when we
/// need to compute the cross-terms.
///
/// The mapping is:
/// - `Column::X(i)` -> i (witness columns, 0 to NUMBER_OF_COLUMNS-1)
/// - `Column::PublicInput(i)` -> NUMBER_OF_COLUMNS + i (public inputs)
/// - `Column::Selector(g)` -> 2 * NUMBER_OF_COLUMNS + gadget_to_index(g) (selectors)
///
/// The [mvpoly::monomials] implementation of the trait [mvpoly::MVPoly]
/// will be used, and the mapping here is consistent with the one expected by
/// this implementation, i.e. we simply map to an increasing number starting at
/// 0, without any gap.
///
/// Note: For cross-term computation, selectors are typically constant and may
/// not need to be included in the multivariate polynomial. However, we provide
/// the mapping for completeness and constraint evaluation.
impl From<Column> for usize {
    fn from(val: Column) -> usize {
        use crate::circuits::selector::gadget_to_index;
        match val {
            Column::X(i) => i,
            Column::PublicInput(i) => NUMBER_OF_COLUMNS + i,
            Column::Selector(gadget) => 2 * NUMBER_OF_COLUMNS + gadget_to_index(gadget),
        }
    }
}

pub type E<Fp> = Expr<ConstantExpr<Fp, ChallengeTerm>, Column>;

impl From<Gadget> for usize {
    fn from(val: Gadget) -> usize {
        match val {
            Gadget::NoOp => 0,
            Gadget::App => 1,
            Gadget::Squaring => 2,
            Gadget::Cubic => 3,
            Gadget::Trivial => 4,
            Gadget::Counter => 5,
            Gadget::Fibonacci => 6,
            Gadget::MinRoot => 7,
            Gadget::EllipticCurveAddition => 8,
            Gadget::EllipticCurveScaling => 9,
            Gadget::PoseidonSpongeAbsorb => 10,
            Gadget::PoseidonFullRound(starting_round) => {
                assert_eq!(starting_round % 5, 0);
                11 + starting_round / 5
            }
            Gadget::PoseidonKimchiFullRound(starting_round) => {
                assert_eq!(starting_round % 5, 0);
                23 + starting_round / 5
            }
            Gadget::SchnorrVerify => 34,
        }
    }
}

// Code to allow for pretty printing of the expressions
impl FormattedOutput for Column {
    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::NoOp => "q_noop".to_string(),
                Gadget::App => "q_app".to_string(),
                Gadget::Squaring => "q_squaring".to_string(),
                Gadget::Cubic => "q_cubic".to_string(),
                Gadget::Trivial => "q_trivial".to_string(),
                Gadget::Counter => "q_counter".to_string(),
                Gadget::Fibonacci => "q_fibonacci".to_string(),
                Gadget::MinRoot => "q_minroot".to_string(),
                Gadget::EllipticCurveAddition => "q_ec_add".to_string(),
                Gadget::EllipticCurveScaling => "q_ec_mul".to_string(),
                Gadget::PoseidonSpongeAbsorb => "q_pos_sponge_absorb".to_string(),
                Gadget::PoseidonFullRound(starting_round) => {
                    format!("q_pos_full_round_{}", starting_round)
                }
                Gadget::PoseidonKimchiFullRound(starting_round) => {
                    format!("q_pos_kimchi_full_round_{}", starting_round)
                }
                Gadget::SchnorrVerify => "q_schnorr_verify".to_string(),
            },
            Column::PublicInput(i) => format!("pi_{{{i}}}").to_string(),
            Column::X(i) => format!("x_{{{i}}}").to_string(),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::NoOp => "q_noop".to_string(),
                Gadget::App => "q_app".to_string(),
                Gadget::Squaring => "q_squaring".to_string(),
                Gadget::Cubic => "q_cubic".to_string(),
                Gadget::Trivial => "q_trivial".to_string(),
                Gadget::Counter => "q_counter".to_string(),
                Gadget::Fibonacci => "q_fibonacci".to_string(),
                Gadget::MinRoot => "q_minroot".to_string(),
                Gadget::EllipticCurveAddition => "q_ec_add".to_string(),
                Gadget::EllipticCurveScaling => "q_ec_mul".to_string(),
                Gadget::PoseidonSpongeAbsorb => "q_pos_sponge_absorb".to_string(),
                Gadget::PoseidonFullRound(starting_round) => {
                    format!("q_pos_full_round_{}", starting_round)
                }
                Gadget::PoseidonKimchiFullRound(starting_round) => {
                    format!("q_pos_kimchi_full_round_{}", starting_round)
                }
                Gadget::SchnorrVerify => "q_schnorr_verify".to_string(),
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
