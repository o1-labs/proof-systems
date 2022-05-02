use crate::circuits::lookup::tables::{LookupTable, RANGE_TABLE_ID};
use ark_ff::Field;

/// A single-column table containing the numbers from 0 to 20
pub fn range_table<F>() -> LookupTable<F>
where
    F: Field,
{
    LookupTable {
        id: RANGE_TABLE_ID,
        data: vec![(0..20u32).map(|i| F::from(i)).collect()],
    }
}
