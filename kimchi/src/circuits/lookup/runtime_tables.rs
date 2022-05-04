//! What are runtime tables?

use crate::circuits::{
    expr::{prologue::*, Column},
    gate::CurrOrNext,
};
use ark_ff::Field;
use serde::{Deserialize, Serialize};

/// The configuration of a runtime table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTableConfiguration {
    /// The table id (must be negative).
    pub id: i32,
    /// The length of the runtime table.
    pub len: usize,
}

/// A runtime table.
#[derive(Debug, Clone)]
pub struct RuntimeTable<F> {
    /// The table id (must be negative).
    pub id: i32,
    /// A single column.
    pub data: Vec<F>,
}

/// Returns the constraints related to the runtime table.
pub fn constraints<F>() -> Vec<E<F>>
where
    F: Field,
{
    // This constrains that runtime_table takes values
    // when selector_RT is 1, and doesn't when selector_RT is 0.
    //
    // runtime_table (1 - selector_RT) = 0
    //
    let var = |x| E::cell(x, CurrOrNext::Curr);

    let rt_check = var(Column::LookupRuntimeTable) * var(Column::LookupRuntimeSelector);

    vec![rt_check]
}
