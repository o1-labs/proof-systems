use crate::circuits::lookup::tables::{LookupTable, RANGE_CHECK_TABLE_ID};
use ark_ff::Field;

/// The range check will be performed on values in `[0, 2^12]`.
const RANGE_UPPERBOUND: u32 = 1 << 12;

/// A single-column table containing the numbers from 0 to [RANGE_UPPERBOUND] (included).
pub fn range_table<F>() -> LookupTable<F>
where
    F: Field,
{
    let range = (0..=RANGE_UPPERBOUND).map(|i| F::from(i)).collect();
    LookupTable {
        id: RANGE_CHECK_TABLE_ID,
        data: vec![range],
    }
}
