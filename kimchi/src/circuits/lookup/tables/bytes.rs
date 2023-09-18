use crate::circuits::lookup::tables::{LookupTable, BYTES_TABLE_ID};
use ark_ff::Field;

/// The table contains all values that fit in one byte, i.e. those in `[0, 2^8)`
pub const BYTES_UPPERBOUND: u32 = 1 << 8;

//~ The lookup table for all bytes.
//~ This is a 1-column table containing all the 2^8 values..

/// Returns the bytes lookup table
///
/// # Panics
///
/// Will panic if `data` is invalid.
pub fn bytes_table<F: Field>() -> LookupTable<F> {
    let table = vec![(0..BYTES_UPPERBOUND).map(F::from).collect()];
    LookupTable {
        id: BYTES_TABLE_ID,
        data: table,
    }
}

pub const TABLE_SIZE: usize = BYTES_UPPERBOUND as usize;
