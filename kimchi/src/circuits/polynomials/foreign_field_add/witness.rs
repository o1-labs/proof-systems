use crate::circuits::{
    polynomial::COLUMNS,
    polynomials::range_check::{
        self, handle_standard_witness_cell, value_to_limb, CopyWitnessCell, ZeroWitnessCell,
    },
};
use ark_ff::FftField;
use array_init::array_init;
use num_bigint::BigUint;
//use num_integer::Integer;
use o1_utils::foreign_field::{foreign_field_element_to_limbs, LIMB_BITS};

//use super::compute_intermediate_products;

pub fn witness<F: FftField>(
    left: &[F; 3],
    right: &[F; 3],
    foreign_modulus: &[F; 3],
) -> [Vec<F>; 2] {
    // TODO: should be little endian, switch to BigUInt
    let [left_input_lo, left_input_mi, left_input_hi] = *left;
    let [right_input_lo, right_input_mi, right_input_hi] = *right;
    let [foreign_modulus_lo, foreign_modulus_mi, foreign_modulus_hi] = *foreign_modulus;
    let two_to_88 = F::from(2u64).pow([88]);

    let max_sub_foreign_modulus_lo: F = two_to_88 - foreign_modulus_lo;
    let max_sub_foreign_modulus_mi: F = two_to_88 - foreign_modulus_mi - F::one();
    let max_sub_foreign_modulus_hi: F = two_to_88 - foreign_modulus_hi - F::one();

    let mut result_lo = left_input_lo + right_input_lo;
    let mut result_mi = left_input_mi + right_input_mi;
    let mut result_hi = left_input_hi + right_input_hi;

    let mut result_carry_lo = if result_lo >= two_to_88 {
        result_mi += F::one();
        result_lo -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let mut result_carry_mi = if result_mi >= two_to_88 {
        result_hi += F::one();
        result_mi -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let field_overflows = result_hi > foreign_modulus_hi
        || (result_hi == foreign_modulus_hi
            && (result_mi > foreign_modulus_mi
                || (result_mi == foreign_modulus_mi && (result_lo >= foreign_modulus_lo))));

    let field_overflow = if field_overflows {
        if result_lo < foreign_modulus_lo {
            result_lo += two_to_88;
            result_mi -= F::one();
            result_carry_lo -= F::one();
        }
        result_lo -= foreign_modulus_lo;
        if result_mi < foreign_modulus_mi {
            result_mi += two_to_88;
            result_hi -= F::one();
            result_carry_mi -= F::one();
        }
        F::one()
    } else {
        F::zero()
    };

    let mut upper_bound_lo = result_lo + max_sub_foreign_modulus_lo;
    let mut upper_bound_mi = result_mi + max_sub_foreign_modulus_mi;
    let mut upper_bound_hi = result_hi + max_sub_foreign_modulus_hi;

    let upper_bound_carry_lo = if upper_bound_lo > two_to_88 {
        upper_bound_mi += F::one();
        upper_bound_lo -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let upper_bound_carry_mi = if upper_bound_mi > two_to_88 {
        upper_bound_hi += F::one();
        upper_bound_mi -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    [
        vec![
            left_input_lo,
            left_input_mi,
            left_input_hi,
            right_input_lo,
            right_input_mi,
            right_input_hi,
            field_overflow,
            result_carry_lo,
            result_carry_mi,
            F::zero(),
            upper_bound_carry_lo,
            upper_bound_carry_mi,
            F::zero(),
            F::zero(),
            F::zero(),
        ],
        vec![
            result_lo,
            result_mi,
            result_hi,
            upper_bound_lo,
            upper_bound_mi,
            upper_bound_hi,
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ],
    ]
}
