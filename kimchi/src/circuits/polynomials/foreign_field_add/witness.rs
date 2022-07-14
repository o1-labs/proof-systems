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
    let [left_input_0, left_input_1, left_input_2] = *left;
    let [right_input_0, right_input_1, right_input_2] = *right;
    let [foreign_modulus_0, foreign_modulus_1, foreign_modulus_2] = *foreign_modulus;
    let two_to_88 = F::from(2u64).pow([88]);

    let max_sub_foreign_modulus_2: F = two_to_88 - foreign_modulus_2;
    let max_sub_foreign_modulus_1: F = two_to_88 - foreign_modulus_1 - F::one();
    let max_sub_foreign_modulus_0: F = two_to_88 - foreign_modulus_0 - F::one();

    let mut result_0 = left_input_0 + right_input_0;
    let mut result_1 = left_input_1 + right_input_1;
    let mut result_2 = left_input_2 + right_input_2;

    let mut result_carry_1 = if result_2 >= two_to_88 {
        result_1 += F::one();
        result_2 -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let mut result_carry_0 = if result_1 >= two_to_88 {
        result_0 += F::one();
        result_1 -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let field_overflows = result_0 > foreign_modulus_0
        || (result_0 == foreign_modulus_0
            && (result_1 > foreign_modulus_1
                || (result_1 == foreign_modulus_1 && (result_2 >= foreign_modulus_2))));

    let field_overflow = if field_overflows {
        if result_2 < foreign_modulus_2 {
            result_2 += two_to_88;
            result_1 -= F::one();
            result_carry_1 -= F::one();
        }
        result_2 -= foreign_modulus_2;
        if result_1 < foreign_modulus_1 {
            result_1 += two_to_88;
            result_0 -= F::one();
            result_carry_0 -= F::one();
        }
        F::one()
    } else {
        F::zero()
    };

    let mut upper_bound_check_0 = result_0 + max_sub_foreign_modulus_0;
    let mut upper_bound_check_1 = result_1 + max_sub_foreign_modulus_1;
    let mut upper_bound_check_2 = result_2 + max_sub_foreign_modulus_2;

    let upper_bound_check_carry_1 = if upper_bound_check_2 > two_to_88 {
        upper_bound_check_1 += F::one();
        upper_bound_check_2 -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    let upper_bound_check_carry_0 = if upper_bound_check_1 > two_to_88 {
        upper_bound_check_0 += F::one();
        upper_bound_check_1 -= two_to_88;
        F::one()
    } else {
        F::zero()
    };

    [
        vec![
            left_input_0,
            left_input_1,
            left_input_2,
            right_input_0,
            right_input_1,
            right_input_2,
            field_overflow,
            result_carry_0,
            result_carry_1,
            upper_bound_check_carry_0,
            upper_bound_check_carry_1,
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ],
        vec![
            result_0,
            result_1,
            result_2,
            upper_bound_check_0,
            upper_bound_check_1,
            upper_bound_check_2,
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
