use kimchi::circuits::expr::{CacheId, ConstantExpr, Expr, FormattedOutput};
use std::collections::HashMap;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

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
    // Permutation argument
    PermutationArgument,
    // Two old gadgets
    SixteenBitsDecomposition,
    BitDecompositionFrom16Bits,
    // Use this one instead to decompose scalar
    BitDecomposition,
    // Elliptic curve related gadgets
    EllipticCurveAddition,
    EllipticCurveScaling,
    Poseidon,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Column {
    Selector(Gadget),
    PublicInput(usize),
    X(usize),
}

pub type E<Fp> = Expr<ConstantExpr<Fp>, Column>;

// Code to allow for pretty printing of the expressions
impl FormattedOutput for Column {
    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::App => "q_app".to_string(),
                Gadget::PermutationArgument => "q_perm".to_string(),
                Gadget::SixteenBitsDecomposition => "q_16bits".to_string(),
                Gadget::BitDecompositionFrom16Bits => "q_bit_from_16bits".to_string(),
                Gadget::BitDecomposition => "q_bits".to_string(),
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
                Gadget::PermutationArgument => "q_perm".to_string(),
                Gadget::SixteenBitsDecomposition => "q_16bits".to_string(),
                Gadget::BitDecompositionFrom16Bits => "q_bit_from_16bits".to_string(),
                Gadget::BitDecomposition => "q_bits".to_string(),
                Gadget::EllipticCurveAddition => "q_ec_add".to_string(),
                Gadget::EllipticCurveScaling => "q_ec_mul".to_string(),
                Gadget::Poseidon => "q_pos".to_string(),
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
