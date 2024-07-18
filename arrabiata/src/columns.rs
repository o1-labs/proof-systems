use std::collections::HashMap;

use kimchi::circuits::expr::{CacheId, ConstantExpr, Expr, FormattedOutput};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Column {
    X(usize),
}

pub type E<Fp> = Expr<ConstantExpr<Fp>, Column>;

// Code to allow for pretty printing of the expressions
impl FormattedOutput for Column {
    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::X(i) => format!("x_{{{i}}}"),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
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
