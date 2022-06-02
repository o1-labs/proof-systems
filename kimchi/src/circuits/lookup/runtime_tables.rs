//! Runtime tables are tables (or arrays) that can be produced during proof creation.
//! The setup has to prepare for their presence using [RuntimeTableConfiguration].
//! At proving time, the prover can use [RuntimeTable] to specify the actual tables.

use crate::circuits::{
    expr::{prologue::*, Column},
    gate::CurrOrNext,
};
use ark_ff::Field;
use serde::{Deserialize, Serialize};

/// The specification of a runtime table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTableSpec {
    /// The table ID.
    pub id: i32,
    /// The number of entries contained in the runtime table.
    pub len: usize,
}

/// Use this type at setup time, to list all the runtime tables.
///
/// Note: care must be taken as table IDs can collide with IDs of other types of lookup tables.
pub enum RuntimeTableCfg<F> {
    /// An indexed runtime table has a counter (starting at zero) in its first column.
    Indexed(RuntimeTableSpec),
    /// A custom runtime table can contain arbitrary values in its first column.
    Custom {
        /// The table ID.
        id: i32,
        /// The content of the first column of the runtime table.
        first_column: Vec<F>,
    },
}

impl<F> RuntimeTableCfg<F> {
    /// Returns the ID of the runtime table.
    pub fn id(&self) -> i32 {
        use RuntimeTableCfg::*;
        match self {
            Indexed(cfg) => cfg.id,
            &Custom { id, .. } => id,
        }
    }

    /// Returns the length of the runtime table.
    pub fn len(&self) -> usize {
        use RuntimeTableCfg::*;
        match self {
            Indexed(cfg) => cfg.len,
            Custom { first_column, .. } => first_column.len(),
        }
    }

    /// Returns `true` if the runtime table is empty.
    pub fn is_empty(&self) -> bool {
        use RuntimeTableCfg::*;
        match self {
            Indexed(cfg) => cfg.len == 0,
            Custom { first_column, .. } => first_column.is_empty(),
        }
    }
}

impl<F> From<RuntimeTableCfg<F>> for RuntimeTableSpec {
    fn from(from: RuntimeTableCfg<F>) -> Self {
        use RuntimeTableCfg::*;
        match from {
            Indexed(cfg) => cfg,
            Custom { id, first_column } => RuntimeTableSpec {
                id,
                len: first_column.len(),
            },
        }
    }
}

/// A runtime table. Runtime tables must match the configuration
/// that was specified in [RuntimeTableCfg].
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
