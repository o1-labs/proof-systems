use crate::circuits::lookup::tables::{LookupTable, XOR_TABLE_ID};
use ark_ff::Field;

//~ The lookup table for 4-bit xor.
//~ Note that it is constructed so that `(0, 0, 0)` is the last position in the table.
//~
//~ This is because tables are extended to the full size of a column (essentially)
//~ by padding them with their final value. And, having the value `(0, 0, 0)` here means
//~ that when we commit to this table and use the dummy value in the `lookup_sorted`
//~ columns, those entries that have the dummy value of
//~
//~ $$0 = 0 + j * 0 + j^2 * 0$$
//~
//~ will translate into a scalar multiplication by 0, which is free.

/// Returns the XOR lookup table
///
/// # Panics
///
/// Will panic if `data` is invalid.
pub fn xor_table<F: Field>() -> LookupTable<F> {
    let mut data = vec![vec![]; 3];

    // XOR for all possible four-bit arguments.
    // I suppose this could be computed a bit faster using symmetry but it's quite
    // small (16*16 = 256 entries) so let's just keep it simple.
    for i in 0u32..=0b1111 {
        for j in 0u32..=0b1111 {
            data[0].push(F::from(i));
            data[1].push(F::from(j));
            data[2].push(F::from(i ^ j));
        }
    }

    for r in &mut data {
        r.reverse();
        // Just to be safe.
        assert!(r[r.len() - 1].is_zero());
    }
    LookupTable {
        id: XOR_TABLE_ID,
        data,
    }
}
