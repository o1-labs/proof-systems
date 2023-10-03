use crate::circuits::lookup::tables::{LookupTable, SPARSE_TABLE_ID};
use ark_ff::Field;

//~ The lookup table for 16-bit expansion for Keccak words encoding.
//~ This is a 1-column table containing the sparse representation of all 16-bit preimages.

/// Returns the sparse lookup table
///
/// # Panics
///
/// Will panic if `data` is invalid.
pub fn sparse_table<F: Field>() -> LookupTable<F> {
    let mut data = vec![vec![]; 2];

    // Sparse expansion table
    for i in 0u64..=0xFFFF {
        data[0].push(F::from(
            u64::from_str_radix(&format!("{:b}", i), 16).unwrap(),
        ));
    }

    LookupTable {
        id: SPARSE_TABLE_ID,
        data,
    }
}

pub const TABLE_SIZE: usize = 65536;
