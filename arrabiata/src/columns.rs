use std::collections::HashMap;

use kimchi::circuits::expr::{CacheId, ConstantExpr, Expr, FormattedOutput};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Gadget {
    SixteenBitsDecomposition,
    BitDecomposition,
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
                Gadget::SixteenBitsDecomposition => "q_16bits".to_string(),
                Gadget::Poseidon => "q_pos".to_string(),
                Gadget::BitDecomposition => "q_bits".to_string(),
            },
            Column::PublicInput(i) => format!("pi_{{{i}}}").to_string(),
            Column::X(i) => format!("x_{{{i}}}").to_string(),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Selector(sel) => match sel {
                Gadget::SixteenBitsDecomposition => "q_16bits".to_string(),
                Gadget::Poseidon => "q_pos".to_string(),
                Gadget::BitDecomposition => "q_bits".to_string(),
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
