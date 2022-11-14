//! Range check table

use crate::circuits::lookup::tables::{LookupTable, RANGE_CHECK_TABLE_ID};
use ark_ff::Field;

/// The range check will be performed on 12-bit values, i.e. those in `[0, 2^12]`
pub const RANGE_CHECK_UPPERBOUND: u32 = 1 << 12;

/// A single-column table containing the numbers from 0 to [`RANGE_CHECK_UPPERBOUND`] (inclusive)
pub fn range_check_table<F>() -> LookupTable<F>
where
    F: Field,
{
    let table = vec![(0..RANGE_CHECK_UPPERBOUND).map(F::from).collect()];
    LookupTable {
        id: RANGE_CHECK_TABLE_ID,
        data: table,
    }
}
