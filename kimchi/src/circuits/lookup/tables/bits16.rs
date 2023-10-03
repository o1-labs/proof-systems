use crate::circuits::lookup::tables::LookupTable;
use ark_ff::Field;

use super::BITS16_TABLE_ID;

//~ The lookup table for 16-bits

/// Returns the lookup table for all 16-bit values
///
/// # Panics
///
/// Will panic if `data` is invalid.
pub fn bits16_table<F: Field>() -> LookupTable<F> {
    let mut data = vec![vec![]; 1];

    // All of the 16-bit values
    for i in 0u64..=0xFFFF {
        data[0].push(F::from(i));
    }

    LookupTable {
        id: BITS16_TABLE_ID,
        data,
    }
}

pub const TABLE_SIZE: usize = 65536;
