//! Range check witness computation

use ark_ff::PrimeField;
use array_init::array_init;
use o1_utils::FieldHelpers;

use crate::circuits::polynomial::COLUMNS;

enum WitnessCell {
    Copy(CopyWitnessCell),
    Value,
    Limb(LimbWitnessCell),
    Zero,
}

// Witness cell copied from another
struct CopyWitnessCell {
    row: usize,
    col: usize,
}
impl CopyWitnessCell {
    const fn create(row: usize, col: usize) -> WitnessCell {
        WitnessCell::Copy(CopyWitnessCell { row, col })
    }
}

// Witness cell for a range check field element limb
struct ValueWitnessCell;
impl ValueWitnessCell {
    const fn create() -> WitnessCell {
        WitnessCell::Value
    }
}

// Witness cell for a range check field element sub-limb
struct LimbWitnessCell {
    row: usize,   // Cell row
    col: usize,   // Cell col
    start: usize, // Starting bit offset
    end: usize,   // Ending bit offset (exclusive)
}
impl LimbWitnessCell {
    // Params: source (row, col), starting bit offset and ending bit offset (exclusive)
    const fn create(row: usize, col: usize, start: usize, end: usize) -> WitnessCell {
        WitnessCell::Limb(LimbWitnessCell {
            row,
            col,
            start,
            end,
        })
    }
}

// An cell containing zero
struct ZeroWitnessCell;
impl ZeroWitnessCell {
    const fn create() -> WitnessCell {
        WitnessCell::Zero
    }
}

// Generate witness in shape that constraints expect (TODO: static for now, make dynamic)
const WITNESS_SHAPE: [[WitnessCell; COLUMNS]; 4] = [
    /* row 1, RangeCheck0 row */
    [
        ValueWitnessCell::create(),
        /* 12-bit plookups */
        LimbWitnessCell::create(0, 0, 0, 12),
        LimbWitnessCell::create(0, 0, 12, 24),
        LimbWitnessCell::create(0, 0, 24, 36),
        LimbWitnessCell::create(0, 0, 36, 48),
        /* 12-bit copies */
        // Copy cells are required because we have a limit
        // of 4 lookups per row.  These two lookups are moved to
        // the 4th row (i.e. Zero circuit gate) and the RangeCheck1
        // circuit gate triggers the lookup constraints.
        LimbWitnessCell::create(0, 0, 48, 60),
        LimbWitnessCell::create(0, 0, 60, 72),
        /* 2-bit crumbs */
        LimbWitnessCell::create(0, 0, 72, 74),
        LimbWitnessCell::create(0, 0, 74, 76),
        LimbWitnessCell::create(0, 0, 76, 78),
        LimbWitnessCell::create(0, 0, 78, 80),
        LimbWitnessCell::create(0, 0, 80, 82),
        LimbWitnessCell::create(0, 0, 82, 84),
        LimbWitnessCell::create(0, 0, 84, 86),
        LimbWitnessCell::create(0, 0, 86, 88),
    ],
    /* row 2, RangeCheck0 row */
    [
        ValueWitnessCell::create(),
        /* 12-bit plookups */
        LimbWitnessCell::create(1, 0, 0, 12),
        LimbWitnessCell::create(1, 0, 12, 24),
        LimbWitnessCell::create(1, 0, 24, 36),
        LimbWitnessCell::create(1, 0, 36, 48),
        /* 12-bit copies (see note about copies above) */
        LimbWitnessCell::create(1, 0, 48, 60),
        LimbWitnessCell::create(1, 0, 60, 72),
        /* 2-bit crumbs */
        LimbWitnessCell::create(1, 0, 72, 74),
        LimbWitnessCell::create(1, 0, 74, 76),
        LimbWitnessCell::create(1, 0, 76, 78),
        LimbWitnessCell::create(1, 0, 78, 80),
        LimbWitnessCell::create(1, 0, 80, 82),
        LimbWitnessCell::create(1, 0, 82, 84),
        LimbWitnessCell::create(1, 0, 84, 86),
        LimbWitnessCell::create(1, 0, 86, 88),
    ],
    /* row 3, RangeCheck1 row */
    [
        ValueWitnessCell::create(),
        /* 12-bit plookups */
        LimbWitnessCell::create(2, 0, 0, 12),
        LimbWitnessCell::create(2, 0, 12, 24),
        LimbWitnessCell::create(2, 0, 24, 36),
        LimbWitnessCell::create(2, 0, 36, 48),
        /* 2-bit crumbs */
        LimbWitnessCell::create(2, 0, 48, 50),
        LimbWitnessCell::create(2, 0, 50, 52),
        LimbWitnessCell::create(2, 0, 52, 54),
        LimbWitnessCell::create(2, 0, 54, 56),
        LimbWitnessCell::create(2, 0, 56, 58),
        LimbWitnessCell::create(2, 0, 58, 60),
        LimbWitnessCell::create(2, 0, 60, 62),
        LimbWitnessCell::create(2, 0, 62, 64),
        LimbWitnessCell::create(2, 0, 64, 66),
        LimbWitnessCell::create(2, 0, 66, 68),
    ],
    /* row 4, Zero row */
    [
        ZeroWitnessCell::create(),
        /* 12-bit plookups (see note about copies above) */
        CopyWitnessCell::create(0, 5),
        CopyWitnessCell::create(0, 6),
        CopyWitnessCell::create(1, 5),
        CopyWitnessCell::create(1, 6),
        /* 2-bit crumbs */
        LimbWitnessCell::create(2, 0, 68, 70),
        LimbWitnessCell::create(2, 0, 70, 72),
        LimbWitnessCell::create(2, 0, 72, 74),
        LimbWitnessCell::create(2, 0, 74, 76),
        LimbWitnessCell::create(2, 0, 76, 78),
        LimbWitnessCell::create(2, 0, 78, 80),
        LimbWitnessCell::create(2, 0, 80, 82),
        LimbWitnessCell::create(2, 0, 82, 84),
        LimbWitnessCell::create(2, 0, 84, 86),
        LimbWitnessCell::create(2, 0, 86, 88),
    ],
];

fn value_to_limb<F: PrimeField>(fe: F, start: usize, end: usize) -> F {
    F::from_bits(&fe.to_bits()[start..end]).expect("failed to deserialize field bits")
}

fn init_range_check_row<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], row: usize, value: F) {
    for col in 0..COLUMNS {
        match &WITNESS_SHAPE[row][col] {
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
}

/// Create a range check witness
/// Input: three values: v0, v1 and v2
pub fn create_witness<F: PrimeField>(v0: F, v1: F, v2: F) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 4]);

    init_range_check_row(&mut witness, 0, v0);
    init_range_check_row(&mut witness, 1, v1);
    init_range_check_row(&mut witness, 2, v2);
    init_range_check_row(&mut witness, 3, F::zero());

    witness
}
