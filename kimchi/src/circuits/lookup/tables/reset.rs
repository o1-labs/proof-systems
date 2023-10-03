use crate::circuits::lookup::tables::LookupTable;
use ark_ff::Field;

use super::RESET_TABLE_ID;

//~ The lookup table for 16-bit expansion for Keccak words encoding.
//~ This is a 2-column table containing the reset sparse representation of the 16-bit values.
//~ The first column contains the 16-bit values, and the second column contains their expansion to 64-bit values.

/// Returns the sparse lookup table
///
/// # Panics
///
/// Will panic if `data` is invalid.
pub fn reset_table<F: Field>() -> LookupTable<F> {
    let mut data = vec![vec![]; 2];

    // Sparse expansion table for all of the 16-bit values
    for i in 0u64..=0xFFFF {
        data[0].push(F::from(i));
        // Uses the fact that the expansion coincides with the hexadecimal interpretation of the index expressed in binary
        // (i.e. expanding 1b gives 0x0001, expanding 0b gives 0x0000)
        data[1].push(F::from(
            u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
        ));
    }

    LookupTable {
        id: RESET_TABLE_ID,
        data,
    }
}

pub const TABLE_SIZE: usize = 65536;
