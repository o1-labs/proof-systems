//! Runtime tables are tables (or arrays) that can be produced during proof creation.
//! The setup has to prepare for their presence using [RuntimeTableConfiguration].
//! At proving time, the prover can use [RuntimeTable] to specify the actual tables.

use crate::circuits::{
    expr::{prologue::*, Column},
    gate::CurrOrNext,
};
use ark_ff::Field;
use serde::{Deserialize, Serialize};

/// The configuration of a runtime table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTableConfiguration {
    /// The table id.
    /// Note that these should be chosen not to collide with other runtime tables' IDs,
    /// as well as other types of lookup tables and their IDs.
    pub id: i32,
    /// The length of the runtime table.
    pub len: usize,
}

/// A runtime table. Runtime tables must match the configuration
/// that was specified via [RuntimeTableConfiguration].
#[derive(Debug, Clone)]
pub struct RuntimeTable<F> {
    /// The table id.
    pub id: i32,
    /// A single column.
    pub data: Vec<F>,
}

/// Returns the constraints related to the runtime tables.
pub fn constraints<F>() -> Vec<E<F>>
where
    F: Field,
{
    // This constrains that runtime_table takes values
    // when selector_RT is 0, and doesn't when selector_RT is 1:
    //
    // runtime_table * selector_RT = 0
    //
    let var = |x| E::cell(x, CurrOrNext::Curr);

    let rt_check = var(Column::LookupRuntimeTable) * var(Column::LookupRuntimeSelector);

    vec![rt_check]
}
