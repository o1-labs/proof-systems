//! Range check witness computation

use ark_ff::PrimeField;
use o1_utils::ForeignElement;
use std::array;

use crate::circuits::witness::Variables;
use crate::{
    circuits::{
        polynomial::COLUMNS,
        witness::{init_row, ConstantCell, CopyBitsCell, CopyCell, VariableCell, WitnessCell},
    },
    variables,
};

/// Witness layout
///   * The values and cell contents are in little-endian order.
///     This is important for compatibility with other gates, where
///     elements of the first 7 columns could be copied and reused by them.
///     So they should be in the usual little-endian witness byte order.
///   * Limbs are mapped to columns so that those containing the MSBs
///     are in lower numbered columns (i.e. big-endian column mapping).
///     This is important so that copy constraints are possible on the MSBs.
///     For example, we can convert the `RangeCheck0` circuit gate into
///     a 64-bit lookup by adding two copy constraints to constrain
///     columns 1 and 2 to zero.
fn layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 4] {
    [
        /* row 1, RangeCheck0 row */
        range_check_0_row("v0", 0),
        /* row 2, RangeCheck0 row */
        range_check_0_row("v1", 1),
        /* row 3, RangeCheck1 row */
        [
            VariableCell::create("v2"),
            /* 2-bit crumbs (placed here to keep lookup pattern */
            /*               the same as RangeCheck0) */
            CopyBitsCell::create(2, 0, 86, 88),
            CopyBitsCell::create(2, 0, 84, 86),
            /* 12-bit plookups */
            CopyBitsCell::create(2, 0, 72, 84),
            CopyBitsCell::create(2, 0, 60, 72),
            CopyBitsCell::create(2, 0, 48, 60),
            CopyBitsCell::create(2, 0, 36, 48),
            /* 2-bit crumbs */
            CopyBitsCell::create(2, 0, 34, 36),
            CopyBitsCell::create(2, 0, 32, 34),
            CopyBitsCell::create(2, 0, 30, 32),
            CopyBitsCell::create(2, 0, 28, 30),
            CopyBitsCell::create(2, 0, 26, 28),
            CopyBitsCell::create(2, 0, 24, 26),
            CopyBitsCell::create(2, 0, 22, 24),
            CopyBitsCell::create(2, 0, 20, 22),
        ],
        /* row 4, Zero row */
        [
            ConstantCell::create(F::zero()),
            /* 2-bit crumbs (placed here to keep lookup pattern */
            /*               the same as RangeCheck0) */
            CopyBitsCell::create(2, 0, 18, 20),
            CopyBitsCell::create(2, 0, 16, 18),
            /* 12-bit plookups (see note about copies in range_check_row) */
            CopyCell::create(0, 1),
            CopyCell::create(0, 2),
            CopyCell::create(1, 1),
            CopyCell::create(1, 2),
            /* 2-bit crumbs */
            CopyBitsCell::create(2, 0, 14, 16),
            CopyBitsCell::create(2, 0, 12, 14),
            CopyBitsCell::create(2, 0, 10, 12),
            CopyBitsCell::create(2, 0, 8, 10),
            CopyBitsCell::create(2, 0, 6, 8),
            CopyBitsCell::create(2, 0, 4, 6),
            CopyBitsCell::create(2, 0, 2, 4),
            CopyBitsCell::create(2, 0, 0, 2),
        ],
    ]
}

/// The row layout for `RangeCheck0`
fn range_check_0_row<F: PrimeField>(
    limb_name: &'static str,
    row: usize,
) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        VariableCell::create(limb_name),
        /* 12-bit copies */
        // Copy cells are required because we have a limit
        // of 4 lookups per row.  These two lookups are moved to
        // the 4th row, which is a Zero circuit gate, and the
        // RangeCheck1 circuit gate triggers the lookup constraints.
        CopyBitsCell::create(row, 0, 76, 88),
        CopyBitsCell::create(row, 0, 64, 76),
        /* 12-bit plookups */
        CopyBitsCell::create(row, 0, 52, 64),
        CopyBitsCell::create(row, 0, 40, 52),
        CopyBitsCell::create(row, 0, 28, 40),
        CopyBitsCell::create(row, 0, 16, 28),
        /* 2-bit crumbs */
        CopyBitsCell::create(row, 0, 14, 16),
        CopyBitsCell::create(row, 0, 12, 14),
        CopyBitsCell::create(row, 0, 10, 12),
        CopyBitsCell::create(row, 0, 8, 10),
        CopyBitsCell::create(row, 0, 6, 8),
        CopyBitsCell::create(row, 0, 4, 6),
        CopyBitsCell::create(row, 0, 2, 4),
        CopyBitsCell::create(row, 0, 0, 2),
    ]
}

/// Create a multi range check witness
/// Input: three 88-bit values: v0, v1 and v2
pub fn create_multi<F: PrimeField>(v0: F, v1: F, v2: F) -> [Vec<F>; COLUMNS] {
    let layout = layout();
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    init_row(&mut witness, 0, 0, &layout, &variables!(v0));
    init_row(&mut witness, 0, 1, &layout, &variables!(v1));
    init_row(&mut witness, 0, 2, &layout, &variables!(v2));
    init_row(&mut witness, 0, 3, &layout, &variables!());

    witness
}

/// Create a single range check witness
/// Input: 88-bit value v0
pub fn create<F: PrimeField>(v0: F) -> [Vec<F>; COLUMNS] {
    let layout = [range_check_0_row("v0", 0)];
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    init_row(&mut witness, 0, 0, &layout, &variables!(v0));

    witness
}

/// Extend an existing witness with a multi-range-check gadget for foreign field element
pub fn extend<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], fe: ForeignElement<F, 3>) {
    let limbs_witness = create_multi(fe[0], fe[1], fe[2]);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}
