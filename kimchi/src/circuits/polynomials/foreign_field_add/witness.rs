use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self,
        witness::{extend_witness, handle_standard_witness_cell, CopyWitnessCell, ZeroWitnessCell},
    },
};
use ark_ff::PrimeField;
use array_init::array_init;
use o1_utils::foreign_field::{ForeignElement, LIMB_BITS};

pub fn create_witness<F: PrimeField>(
    left_input: ForeignElement<F, 3>,
    right_input: ForeignElement<F, 3>,
    foreign_modulus: ForeignElement<F, 3>,
) -> [Vec<F>; COLUMNS] {
    let two_to_limb = F::from(2u128.pow(LIMB_BITS));

    let mut witness = array_init(|_| vec![F::zero(); 0]);

    // Create multi-range-check witness for left_input and right_input
    extend_witness(&mut witness, left_input);
    extend_witness(&mut witness, right_input);

    // Compute helper variables for the upper bound check
    let max_sub_foreign_modulus = ForeignElement::<F, 3>::new([
        two_to_limb - foreign_modulus.lo(),
        two_to_limb - foreign_modulus.mi() - F::one(),
        two_to_limb - foreign_modulus.hi() - F::one(),
    ]);

    // Compute addition of limbs of inputs (may exceed 88 bits, but at most once)
    let mut result_lo = *left_input.lo() + *right_input.lo();
    let mut result_mi = *left_input.mi() + *right_input.mi();
    let mut result_hi = *left_input.hi() + *right_input.hi();

    // If low limb of result exceeds limb-length, subtract modulus from low limb and add 1 carry to middle limb result
    let mut result_carry_lo = if result_lo >= two_to_limb {
        result_mi += F::one();
        result_lo -= two_to_limb;
        F::one()
    } else {
        F::zero()
    };

    // If middle limb of result exceeds limb-length, subtract modulus from middle limb and add 1 carry to high limb result
    let mut result_carry_mi = if result_mi >= two_to_limb {
        result_hi += F::one();
        result_mi -= two_to_limb;
        F::one()
    } else {
        F::zero()
    };

    // Using the BigUint library, the following should be easier. We would compute result at the beginning and obtain the field overflow trivially

    // Compute field overflow bit (if any)
    // It must be the case that the concatenation of the three limbs is larger than the modulus
    let field_overflows = result_hi > *foreign_modulus.hi()
        || (result_hi == *foreign_modulus.hi()
            && (result_mi > *foreign_modulus.mi()
                || (result_mi == *foreign_modulus.mi() && (result_lo >= *foreign_modulus.lo()))));

    // If there was field overflow, we need to adjust the values of the result limbs
    // to obtain the equation a + b = o · m + r -> with o = 1
    // by (roughly speaking) subtracting one modulus to the result
    let field_overflow = if field_overflows {
        // If the lower limb of the result is smaller than the lower limb of the modulus,
        // we start adding the term 10....0 with 88 zeros to the lower limb of the result for the subtraction
        // and then subtract 1 to the middle limb of the result (the above term)
        // to subtract 1 to the low carry of the result
        // and finally subtract the lower limb of the modulus from the lower limb of the result
        if result_lo < *foreign_modulus.lo() {
            result_lo += two_to_limb;
            result_mi -= F::one();
            result_carry_lo -= F::one();
        }
        result_lo -= *foreign_modulus.lo();

        // If the middle limb of the result is smaller than the middle limb of the modulus,
        // we start adding the term 10....0 with 88 zeros to the middle limb of the result
        // and then subtract 1 to the high limb of the result (the above term)
        // to subtract 1 to the middle carry of the result
        // and finally subtract the middle limb of the modulus from the middle limb of the result
        if result_mi < *foreign_modulus.mi() {
            result_mi += two_to_limb;
            result_hi -= F::one();
            result_carry_mi -= F::one();
        }
        result_mi -= *foreign_modulus.mi();

        if result_hi < *foreign_modulus.hi() {
            result_hi += two_to_limb;
        }
        result_hi -= *foreign_modulus.hi();

        F::one()
    } else {
        F::zero()
    };

    let mut upper_bound_lo = result_lo + *max_sub_foreign_modulus.lo();
    let mut upper_bound_mi = result_mi + *max_sub_foreign_modulus.mi();
    let mut upper_bound_hi = result_hi + *max_sub_foreign_modulus.hi();

    // If the lower upper bound sum exceeds the limb-length then subtract 2^88 and add one to the middle limb
    let upper_bound_carry_lo = if upper_bound_lo > two_to_limb {
        upper_bound_mi += F::one();
        upper_bound_lo -= two_to_limb;
        F::one()
    } else {
        F::zero()
    };

    // If the middle upper bound sum exceeds the limb-length then subtract 2^88 and add one to the high limb
    let upper_bound_carry_mi = if upper_bound_mi > two_to_limb {
        upper_bound_hi += F::one();
        upper_bound_mi -= two_to_limb;
        F::one()
    } else {
        F::zero()
    };

    let result = ForeignElement::<F, 3>::new([result_lo, result_mi, result_hi]);
    let upper_bound = ForeignElement::<F, 3>::new([upper_bound_lo, upper_bound_mi, upper_bound_hi]);

    extend_witness(&mut witness, result);
    extend_witness(&mut witness, upper_bound);

    let result_carry = [result_carry_lo, result_carry_mi];
    let upper_bound_carry = [upper_bound_carry_lo, upper_bound_carry_mi];

    // Create foreign field addition and zero witness rows
    for w in &mut witness {
        w.extend(std::iter::repeat(F::zero()).take(2));
    }

    let offset = 16; // number of witness rows of the gadget before the first row of the addition gate

    // ForeignFieldAdd row and Zero row
    init_foreign_field_add_rows(
        &mut witness,
        offset,
        field_overflow,
        result_carry,
        upper_bound_carry,
    );

    witness
}

// Extend standard WitnessCell to support foreign field addition
// specific cell types
//
//     * ValueLimb := contiguous range of bits extracted a value
//
// TODO: Currently located in range check, but could be moved elsewhere
pub enum WitnessCell {
    Standard(range_check::witness::WitnessCell),
    FieldElem(FieldElemWitnessCell),
}

// Witness cell containing a type of value that is a field element
pub enum FieldElemType {
    FieldOverflow,
    ResultCarry,
    UpperBoundCarry,
}

#[derive(Copy, Clone)]
pub enum FieldElemOrder {
    No = -1,
    Lo = 0,
    Mi = 1,
    Hi = 2,
}

pub struct FieldElemWitnessCell {
    pub kind: FieldElemType,
    pub order: FieldElemOrder,
}

impl FieldElemWitnessCell {
    pub const fn create(kind: FieldElemType, order: FieldElemOrder) -> WitnessCell {
        WitnessCell::FieldElem(FieldElemWitnessCell { kind, order })
    }
}

const WITNESS_SHAPE: [[WitnessCell; COLUMNS]; 2] = [
    // ForeignFieldAdd row
    [
        WitnessCell::Standard(CopyWitnessCell::create(0, 0)), // left_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(1, 0)), // left_input_mi
        WitnessCell::Standard(CopyWitnessCell::create(2, 0)), // left_input_hi
        WitnessCell::Standard(CopyWitnessCell::create(4, 0)), // right_input_lo
        WitnessCell::Standard(CopyWitnessCell::create(5, 0)), // right_input_mi
        WitnessCell::Standard(CopyWitnessCell::create(6, 0)), // right_input_hi
        FieldElemWitnessCell::create(FieldElemType::FieldOverflow, FieldElemOrder::No), // field_overflow
        FieldElemWitnessCell::create(FieldElemType::ResultCarry, FieldElemOrder::Lo), // result_carry_lo
        FieldElemWitnessCell::create(FieldElemType::ResultCarry, FieldElemOrder::Mi), // result_carry_mi
        FieldElemWitnessCell::create(FieldElemType::UpperBoundCarry, FieldElemOrder::Lo), // upper_bound_carry_lo
        FieldElemWitnessCell::create(FieldElemType::UpperBoundCarry, FieldElemOrder::Mi), // upper_bound_carry_mi
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
    // Zero row
    [
        WitnessCell::Standard(CopyWitnessCell::create(8, 0)), // result_lo
        WitnessCell::Standard(CopyWitnessCell::create(9, 0)), // result_mi
        WitnessCell::Standard(CopyWitnessCell::create(10, 0)), // result_hi
        WitnessCell::Standard(CopyWitnessCell::create(12, 0)), // upper_bound_lo
        WitnessCell::Standard(CopyWitnessCell::create(13, 0)), // upper_bound_mi
        WitnessCell::Standard(CopyWitnessCell::create(14, 0)), // upper_bound_hi
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
        WitnessCell::Standard(ZeroWitnessCell::create()),
    ],
];

fn init_foreign_field_add_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    offset: usize,
    field_overflow: F,
    result_carry: [F; 2],
    upper_bound_carry: [F; 2],
) {
    for (row, wit) in WITNESS_SHAPE.iter().enumerate() {
        for col in 0..COLUMNS {
            match &wit[col] {
                WitnessCell::Standard(standard_cell) => {
                    handle_standard_witness_cell(
                        witness,
                        standard_cell,
                        offset + row,
                        col,
                        F::zero(), /* unused by this gate */
                    )
                }
                WitnessCell::FieldElem(elem_cell) => {
                    witness[col][offset + row] = {
                        match elem_cell.kind {
                            FieldElemType::FieldOverflow => field_overflow,
                            FieldElemType::ResultCarry => result_carry[elem_cell.order as usize],
                            FieldElemType::UpperBoundCarry => {
                                upper_bound_carry[elem_cell.order as usize]
                            }
                        }
                    }
                }
            }
        }
    }
}
