//! Range check witness computation

use ark_ff::PrimeField;
use std::array;
use o1_utils::{FieldHelpers, ForeignElement};

use crate::circuits::polynomial::COLUMNS;

/// Witness cell for range check gadget
pub enum WitnessCell {
    Copy(CopyWitnessCell),
    Value,
    Limb(LimbWitnessCell),
    Zero,
}

/// Witness cell copied from another
pub struct CopyWitnessCell {
    row: usize,
    col: usize,
}

impl CopyWitnessCell {
    /// Create a copy witness cell
    pub const fn create(row: usize, col: usize) -> WitnessCell {
        WitnessCell::Copy(CopyWitnessCell { row, col })
    }
}

/// Witness cell for a range check field element limb
pub struct ValueWitnessCell;

impl ValueWitnessCell {
    /// Create a value witness cell
    pub const fn create() -> WitnessCell {
        WitnessCell::Value
    }
}

/// Witness cell for a range check field element sub-limb
pub struct LimbWitnessCell {
    row: usize,   // Cell row
    col: usize,   // Cell col
    start: usize, // Starting bit offset
    end: usize,   // Ending bit offset (exclusive)
}

impl LimbWitnessCell {
    /// Creates a limb witness cell.
    /// Params: source (row, col), starting bit offset and ending bit offset (exclusive)
    pub const fn create(row: usize, col: usize, start: usize, end: usize) -> WitnessCell {
        WitnessCell::Limb(LimbWitnessCell {
            row,
            col,
            start,
            end,
        })
    }
}

/// A cell containing zero
pub struct ZeroWitnessCell;

impl ZeroWitnessCell {
    /// Create a zero witness cell
    pub const fn create() -> WitnessCell {
        WitnessCell::Zero
    }
}

/// Witness layout
///   * The values and cell contents are in little-endian order.
///     This is important for compatibility with other gates, where
///     elements of the first 7 columns could be copied and reused by them.
///     So they should be in the usual little-endian witness byte order.
///   * Limbs are mapped to columns so that those containing the MSBs
///     are in lower numbered columns (i.e. big-endian column mapping).
///     This is important so that copy constraints are possible on the MSBs.
///     For example, we can convert the RangeCheck0 circuit gate into
///     a 64-bit lookup by adding two copy constraints to constrain
///     columns 1 and 2 to zero.
pub const WITNESS_SHAPE: [[WitnessCell; COLUMNS]; 4] = [
    /* row 1, RangeCheck0 row */
    range_check_row(0),
    /* row 2, RangeCheck0 row */
    range_check_row(1),
    /* row 3, RangeCheck1 row */
    [
        ValueWitnessCell::create(),
        /* 2-bit crumbs (placed here to keep lookup pattern */
        /*               the same as RangeCheck0) */
        LimbWitnessCell::create(2, 0, 86, 88),
        LimbWitnessCell::create(2, 0, 84, 86),
        /* 12-bit plookups */
        LimbWitnessCell::create(2, 0, 72, 84),
        LimbWitnessCell::create(2, 0, 60, 72),
        LimbWitnessCell::create(2, 0, 48, 60),
        LimbWitnessCell::create(2, 0, 36, 48),
        /* 2-bit crumbs */
        LimbWitnessCell::create(2, 0, 34, 36),
        LimbWitnessCell::create(2, 0, 32, 34),
        LimbWitnessCell::create(2, 0, 30, 32),
        LimbWitnessCell::create(2, 0, 28, 30),
        LimbWitnessCell::create(2, 0, 26, 28),
        LimbWitnessCell::create(2, 0, 24, 26),
        LimbWitnessCell::create(2, 0, 22, 24),
        LimbWitnessCell::create(2, 0, 20, 22),
    ],
    /* row 4, Zero row */
    [
        ZeroWitnessCell::create(),
        /* 2-bit crumbs (placed here to keep lookup pattern */
        /*               the same as RangeCheck0) */
        LimbWitnessCell::create(2, 0, 18, 20),
        LimbWitnessCell::create(2, 0, 16, 18),
        /* 12-bit plookups (see note about copies in range_check_row) */
        CopyWitnessCell::create(0, 1),
        CopyWitnessCell::create(0, 2),
        CopyWitnessCell::create(1, 1),
        CopyWitnessCell::create(1, 2),
        /* 2-bit crumbs */
        LimbWitnessCell::create(2, 0, 14, 16),
        LimbWitnessCell::create(2, 0, 12, 14),
        LimbWitnessCell::create(2, 0, 10, 12),
        LimbWitnessCell::create(2, 0, 8, 10),
        LimbWitnessCell::create(2, 0, 6, 8),
        LimbWitnessCell::create(2, 0, 4, 6),
        LimbWitnessCell::create(2, 0, 2, 4),
        LimbWitnessCell::create(2, 0, 0, 2),
    ],
];

/// The row layout for RangeCheck0
const fn range_check_row(row: usize) -> [WitnessCell; COLUMNS] {
    [
        ValueWitnessCell::create(),
        /* 12-bit copies */
        // Copy cells are required because we have a limit
        // of 4 lookups per row.  These two lookups are moved to
        // the 4th row, which is a Zero circuit gate, and the
        // RangeCheck1 circuit gate triggers the lookup constraints.
        LimbWitnessCell::create(row, 0, 76, 88),
        LimbWitnessCell::create(row, 0, 64, 76),
        /* 12-bit plookups */
        LimbWitnessCell::create(row, 0, 52, 64),
        LimbWitnessCell::create(row, 0, 40, 52),
        LimbWitnessCell::create(row, 0, 28, 40),
        LimbWitnessCell::create(row, 0, 16, 28),
        /* 2-bit crumbs */
        LimbWitnessCell::create(row, 0, 14, 16),
        LimbWitnessCell::create(row, 0, 12, 14),
        LimbWitnessCell::create(row, 0, 10, 12),
        LimbWitnessCell::create(row, 0, 8, 10),
        LimbWitnessCell::create(row, 0, 6, 8),
        LimbWitnessCell::create(row, 0, 4, 6),
        LimbWitnessCell::create(row, 0, 2, 4),
        LimbWitnessCell::create(row, 0, 0, 2),
    ]
}

/// transforms a field to a limb from a start bit to an end bit
pub fn value_to_limb<F: PrimeField>(fe: F, start: usize, end: usize) -> F {
    F::from_bits(&fe.to_bits()[start..end]).expect("failed to deserialize field bits")
}

/// handles range-check witness cells
pub fn handle_standard_witness_cell<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    witness_cell: &WitnessCell,
    row: usize,
    col: usize,
    value: F,
) {
    match witness_cell {
        WitnessCell::Copy(copy_cell) => {
            witness[col][row] = witness[copy_cell.col][copy_cell.row];
        }
        WitnessCell::Value => {
            witness[col][row] = value;
        }
        WitnessCell::Limb(limb_cell) => {
            witness[col][row] = value_to_limb(
                witness[limb_cell.col][limb_cell.row], // limb cell (row, col)
                limb_cell.start,                       // starting bit
                limb_cell.end,                         // ending bit (exclusive)
            );
        }
        WitnessCell::Zero => {
            witness[col][row] = F::zero();
        }
    }
}

/// initialize a range_check_row
fn init_range_check_row<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], row: usize, value: F) {
    for col in 0..COLUMNS {
        handle_standard_witness_cell(witness, &WITNESS_SHAPE[row][col], row, col, value);
    }
}

/// Create a multi range check witness
/// Input: three 88-bit values: v0, v1 and v2
pub fn create_multi_witness<F: PrimeField>(v0: F, v1: F, v2: F) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    init_range_check_row(&mut witness, 0, v0);
    init_range_check_row(&mut witness, 1, v1);
    init_range_check_row(&mut witness, 2, v2);
    init_range_check_row(&mut witness, 3, F::zero());

    witness
}

/// Create a single range check witness
/// Input: 88-bit value v0
pub fn create_witness<F: PrimeField>(v0: F) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    init_range_check_row(&mut witness, 0, v0);

    witness
}

/// Extend an existing witness with a multi-range-check gate for foreign field
/// elements fe
pub fn extend_witness<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], fe: ForeignElement<F, 3>) {
    let limbs_witness = create_multi_witness(*fe.lo(), *fe.mi(), *fe.hi());
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}
