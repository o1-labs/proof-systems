//! Range check witness computation

use ark_ff::PrimeField;
use core::array;
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::{field_helpers::BigUintFieldHelpers, FieldHelpers, ForeignElement};

use crate::{
    circuits::{
        polynomial::COLUMNS,
        polynomials::foreign_field_common::{BigUintForeignFieldHelpers, LIMB_BITS},
        witness::{init_row, CopyBitsCell, CopyCell, VariableCell, Variables, WitnessCell},
    },
    variable_map, variables,
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
fn layout<F: PrimeField>() -> [Vec<Box<dyn WitnessCell<F>>>; 4] {
    [
        /* row 1, RangeCheck0 row */
        range_check_0_row("v0", 0),
        /* row 2, RangeCheck0 row */
        range_check_0_row("v1", 1),
        /* row 3, RangeCheck1 row */
        vec![
            VariableCell::create("v2"),
            VariableCell::create("v12"), // optional
            /* 2-bit crumbs (placed here to keep lookup pattern */
            /*               the same as RangeCheck0) */
            CopyBitsCell::create(2, 0, 86, 88),
            /* 12-bit plookups */
            CopyBitsCell::create(2, 0, 74, 86),
            CopyBitsCell::create(2, 0, 62, 74),
            CopyBitsCell::create(2, 0, 50, 62),
            CopyBitsCell::create(2, 0, 38, 50),
            /* 2-bit crumbs */
            CopyBitsCell::create(2, 0, 36, 38),
            CopyBitsCell::create(2, 0, 34, 36),
            CopyBitsCell::create(2, 0, 32, 34),
            CopyBitsCell::create(2, 0, 30, 32),
            CopyBitsCell::create(2, 0, 28, 30),
            CopyBitsCell::create(2, 0, 26, 28),
            CopyBitsCell::create(2, 0, 24, 26),
            CopyBitsCell::create(2, 0, 22, 24),
        ],
        /* row 4, Zero row */
        vec![
            CopyBitsCell::create(2, 0, 20, 22),
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
pub fn range_check_0_row<F: PrimeField>(
    limb_name: &'static str,
    row: usize,
) -> Vec<Box<dyn WitnessCell<F>>> {
    vec![
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

/// Create a multi range check witness from three 88-bit values: v0, v1 and v2
pub fn create_multi<F: PrimeField>(v0: F, v1: F, v2: F) -> [Vec<F>; COLUMNS] {
    let layout = layout();
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    init_row(&mut witness, 0, 0, &layout, &variables!(v0));
    init_row(&mut witness, 0, 1, &layout, &variables!(v1));
    init_row(
        &mut witness,
        0,
        2,
        &layout,
        &variable_map!("v2" => v2, "v12" => F::zero()),
    );
    init_row(&mut witness, 0, 3, &layout, &variables!());

    witness
}

/// Create a multi range check witness from two limbs: v01 (176 bits), v2 (88 bits),
/// where v2 is the most significant limb and v01 is the least significant limb
pub fn create_multi_compact<F: PrimeField>(v01: F, v2: F) -> [Vec<F>; COLUMNS] {
    let layout = layout();
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 4]);

    let (v1, v0) = v01.to_biguint().div_rem(&BigUint::two_to_limb());
    let v0: F = v0.to_field().expect("failed to convert to field element");
    let v1: F = v1.to_field().expect("failed to convert to field element");

    init_row(&mut witness, 0, 0, &layout, &variable_map!("v0" => v2));
    init_row(&mut witness, 0, 1, &layout, &variable_map!("v1" => v0));

    init_row(
        &mut witness,
        0,
        2,
        &layout,
        &variable_map!("v2" => v1, "v12" => v01),
    );
    init_row(&mut witness, 0, 3, &layout, &variables!());

    witness
}

/// Create a multi range check witness from limbs
pub fn create_multi_limbs<F: PrimeField>(limbs: &[F; 3]) -> [Vec<F>; COLUMNS] {
    create_multi(limbs[0], limbs[1], limbs[2])
}

/// Create a multi range check witness from compact limbs
pub fn create_multi_compact_limbs<F: PrimeField>(limbs: &[F; 2]) -> [Vec<F>; COLUMNS] {
    create_multi_compact(limbs[0], limbs[1])
}

/// Create a single range check witness
/// Input: 88-bit value v0
pub fn create<F: PrimeField>(v0: F) -> [Vec<F>; COLUMNS] {
    let layout = vec![range_check_0_row("v0", 0)];
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);

    init_row(&mut witness, 0, 0, &layout, &variables!(v0));

    witness
}

/// Extend an existing witness with a multi-range-check gadget for three 88-bit values: v0, v1 and v2
pub fn extend_multi<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], v0: F, v1: F, v2: F) {
    let limbs_witness = create_multi(v0, v1, v2);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}

/// Extend and existing witness with a multi range check witness for two limbs: v01 (176 bits), v2 (88 bits),
/// where v2 is the most significant limb and v01 is the least significant limb
pub fn extend_multi_compact<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], v01: F, v2: F) {
    let limbs_witness = create_multi_compact(v01, v2);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}

/// Extend an existing witness with a multi-range-check gadget for limbs
pub fn extend_multi_limbs<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], limbs: &[F; 3]) {
    let limbs_witness = create_multi_limbs(limbs);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}

/// Extend an existing witness with a multi-range-check gadget for compact limbs
pub fn extend_multi_compact_limbs<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], limbs: &[F; 2]) {
    let limbs_witness = create_multi_compact_limbs(limbs);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}

/// Extend an existing witness with a multi-range-check gadget for ForeignElement
pub fn extend_multi_from_fe<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    fe: &ForeignElement<F, LIMB_BITS, 3>,
) {
    extend_multi(witness, fe.limbs[0], fe.limbs[1], fe.limbs[2]);
}

/// Extend an existing witness with a single range check witness for foreign field element
pub fn extend<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], fe: F) {
    let limbs_witness = create(fe);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}

/// Extend an existing witness with a single-range-check gate for 88bits
pub fn extend_single<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], elem: F) {
    let single_wit = create(elem);
    for col in 0..COLUMNS {
        witness[col].extend(single_wit[col].iter())
    }
}
