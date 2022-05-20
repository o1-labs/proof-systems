//! Witness computation

/// TODO: make dynamic
use ark_ff::PrimeField;
use array_init::array_init;
use num_bigint::BigUint;
use o1_utils::FieldHelpers;

use crate::circuits::polynomial::COLUMNS;

// The maximum supported range check element size is 264-bits
const MAX_LIMBS: usize = 3;
const LIMB_SIZE: usize = 88;

enum WitnessCell {
    Copy(CopyWitnessCell),
    Limb,
    Sublimb(SublimbWitnessCell),
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
struct LimbWitnessCell;
impl LimbWitnessCell {
    const fn create() -> WitnessCell {
        WitnessCell::Limb
    }
}

// Witness cell for a range check field element sub-limb
struct SublimbWitnessCell {
    row: usize,   // Cell row
    col: usize,   // Cell col
    start: usize, // Starting bit offset
    end: usize,   // Ending bit offset (exclusive)
}
impl SublimbWitnessCell {
    // Params: source (row, col), starting bit offset and ending bit offset (exclusive)
    const fn create(row: usize, col: usize, start: usize, end: usize) -> WitnessCell {
        WitnessCell::Sublimb(SublimbWitnessCell {
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
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(0, 0, 0, 12),
        SublimbWitnessCell::create(0, 0, 12, 24),
        SublimbWitnessCell::create(0, 0, 24, 36),
        SublimbWitnessCell::create(0, 0, 36, 48),
        /* 12-bit copies */
        // Copy cells are required because we have a limit
        // of 4 lookups per row.  These two lookups are deferred
        // until the RangeCheck2 gate, which handles them.
        SublimbWitnessCell::create(0, 0, 48, 60),
        SublimbWitnessCell::create(0, 0, 60, 72),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(0, 0, 72, 74),
        SublimbWitnessCell::create(0, 0, 74, 76),
        SublimbWitnessCell::create(0, 0, 76, 78),
        SublimbWitnessCell::create(0, 0, 78, 80),
        SublimbWitnessCell::create(0, 0, 80, 82),
        SublimbWitnessCell::create(0, 0, 82, 84),
        SublimbWitnessCell::create(0, 0, 84, 86),
        SublimbWitnessCell::create(0, 0, 86, 88),
    ],
    /* row 2, RangeCheck0 row */
    [
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(1, 0, 0, 12),
        SublimbWitnessCell::create(1, 0, 12, 24),
        SublimbWitnessCell::create(1, 0, 24, 36),
        SublimbWitnessCell::create(1, 0, 36, 48),
        /* 12-bit copies (see note about copies above) */
        SublimbWitnessCell::create(1, 0, 48, 60),
        SublimbWitnessCell::create(1, 0, 60, 72),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(1, 0, 72, 74),
        SublimbWitnessCell::create(1, 0, 74, 76),
        SublimbWitnessCell::create(1, 0, 76, 78),
        SublimbWitnessCell::create(1, 0, 78, 80),
        SublimbWitnessCell::create(1, 0, 80, 82),
        SublimbWitnessCell::create(1, 0, 82, 84),
        SublimbWitnessCell::create(1, 0, 84, 86),
        SublimbWitnessCell::create(1, 0, 86, 88),
    ],
    /* row 3, RangeCheck1 row */
    [
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(2, 0, 0, 12),
        SublimbWitnessCell::create(2, 0, 12, 24),
        SublimbWitnessCell::create(2, 0, 24, 36),
        SublimbWitnessCell::create(2, 0, 36, 48),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(2, 0, 48, 50),
        SublimbWitnessCell::create(2, 0, 50, 52),
        SublimbWitnessCell::create(2, 0, 52, 54),
        SublimbWitnessCell::create(2, 0, 54, 56),
        SublimbWitnessCell::create(2, 0, 56, 58),
        SublimbWitnessCell::create(2, 0, 58, 60),
        SublimbWitnessCell::create(2, 0, 60, 62),
        SublimbWitnessCell::create(2, 0, 62, 64),
        SublimbWitnessCell::create(2, 0, 64, 66),
        SublimbWitnessCell::create(2, 0, 66, 68),
    ],
    /* row 4, RangeCheck2 row */
    [
        ZeroWitnessCell::create(),
        /* 12-bit plookups (see note about copies above) */
        CopyWitnessCell::create(0, 5),
        CopyWitnessCell::create(0, 6),
        CopyWitnessCell::create(1, 5),
        CopyWitnessCell::create(1, 6),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(2, 0, 68, 70),
        SublimbWitnessCell::create(2, 0, 70, 72),
        SublimbWitnessCell::create(2, 0, 72, 74),
        SublimbWitnessCell::create(2, 0, 74, 76),
        SublimbWitnessCell::create(2, 0, 76, 78),
        SublimbWitnessCell::create(2, 0, 78, 80),
        SublimbWitnessCell::create(2, 0, 80, 82),
        SublimbWitnessCell::create(2, 0, 82, 84),
        SublimbWitnessCell::create(2, 0, 84, 86),
        SublimbWitnessCell::create(2, 0, 86, 88),
    ],
];

fn limb_to_sublimb<F: PrimeField>(fe: F, start: usize, end: usize) -> F {
    F::from_bits(&fe.to_bits()[start..end]).expect("failed to deserialize field bits")
}

fn init_range_check_row<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], row: usize, limb: F) {
    for col in 0..COLUMNS {
        match &WITNESS_SHAPE[row][col] {
            WitnessCell::Copy(copy_cell) => {
                witness[col][row] = witness[copy_cell.col][copy_cell.row];
            }
            WitnessCell::Limb => {
                witness[col][row] = limb;
            }
            WitnessCell::Sublimb(sublimb_cell) => {
                witness[col][row] = limb_to_sublimb(
                    witness[sublimb_cell.col][sublimb_cell.row], // limb cell (row, col)
                    sublimb_cell.start,                          // starting bit
                    sublimb_cell.end,                            // ending bit (exclusive)
                );
            }
            WitnessCell::Zero => {
                witness[col][row] = F::zero();
            }
        }
    }
}

fn append_range_check_field_element_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    fe: BigUint,
) {
    assert!(fe.bits() <= (MAX_LIMBS * LIMB_SIZE) as u64);
    let mut last_row_number = 0;

    for (row, chunk) in fe
        .to_bytes_le() // F::from_bytes() below is little-endian
        .chunks(LIMB_SIZE / 8 + (LIMB_SIZE % 8 != 0) as usize)
        .enumerate()
    {
        // Convert chunk to field element and store in column 0
        let mut limb_bytes = chunk.to_vec();
        limb_bytes.resize(32 /* F::size_in_bytes() */, 0);
        let limb_fe = F::from_bytes(&limb_bytes).expect("failed to deserialize limb field bytes");

        // Initialize the row based on the limb and public input shape
        init_range_check_row(witness, row, limb_fe);
        last_row_number += 1;
    }

    // Initialize last row
    init_range_check_row(witness, last_row_number, F::zero());
}

/// Create a range check witness
pub fn create_witness<F: PrimeField>(fe: BigUint) -> [Vec<F>; COLUMNS] {
    assert!(fe.bits() <= (MAX_LIMBS * LIMB_SIZE) as u64);
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 4]);
    append_range_check_field_element_rows(&mut witness, fe);
    witness
}
