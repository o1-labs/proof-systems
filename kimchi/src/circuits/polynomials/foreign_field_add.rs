//! This module implements foreign field addition.
//!
//! ```text
//! let a_1, a_2, a_3 be 88-bit limbs of the left element
//! let b_1, b_2, b_3 be 88-bit limbs of the right element
//! let m_1, m_2, m_3 be 88-bit limbs of the modulus
//!
//! Then the limbs of the result are
//! r_1 = a_1 + b_1 - x * m_1 + y_1
//! r_2 = a_2 + b_2 - x * m_2 - 2^88 * y_1 + y_2
//! r_3 = a_3 + b_3 - x * m_3 - 2^88 * y_2
//!
//! x = 0 or 1 handles overflows in the field
//! y_i = -1, 0, 1 are auxiliary variables that handle carries between limbs
//!
//! We need to do an additional range check to make sure that the result is < the modulus, by
//! adding 2^(3*88) - m. (This can be computed easily from the limbs of m.) Represent this as limbs
//! k_1, k_2, k_3.
//! The overflow check can be calculated as
//! o_1 = r_1 + k_1 + z_1
//! o_2 = r_2 + k_2 - z_1 * 2^88 + z_2
//! o_3 = r_3 + k_3 - z_2 * 2^88
//!
//! z_i = 0 or 1 are auxiliary variables that handle carries between limbs
//!
//! Then, range check r and o. The range check of o can be skipped if there are multiple additions
//! and r is an intermediate value that is unused elsewhere (since the final r must have had the
//! right number of moduluses subtracted along the way).
//!
//! You could lay this out as a double-width gate, e.g.
//! a_1 a_2 a_3 b_1 b_2 b_3 x y_1 y_2 z_1 z_2
//! r_1 r_2 r_3 o_1 o_2 o_3
//! ```
//!
//!    | col | `ForeignFieldAdd' | `Zero`      |
//!    | --- | ----------------- | ----------- |
//!    |   0 | `a1` (copy)       | `r1` (copy) |
//!    |   1 | `a2` (copy)       | `r2` (copy) |
//!    |   2 | `a3` (copy)       | `r3` (copy) |
//!    |   3 | `b1` (copy)       | `o1` (copy) |
//!    |   4 | `b2` (copy)       | `o2` (copy) |
//!    |   5 | `b3` (copy)       | `o3` (copy) |
//!    |   6 | `x`               |             |
//!    |   7 | `y1`              |             |
//!    |   8 | `y2`              |             |
//!    |   9 | `z1`              |             |
//!    |  10 | `z2`              |             |
//!    |  11 |                   |             |
//!    |  12 |                   |             |
//!    |  13 |                   |             |
//!    |  14 |                   |             |
//!
//!  Documentation:
//!
//!   For more details please see https://hackmd.io/7qnPOasqTTmElac8Xghnrw?view
//!
//!   Mapping:
//!     To make things clearer, the following mapping between the variable names
//!     used in the code and those of the document can be helpful.
//!
//!     left_input_0 => a1  right_input_0 => b1  result_0 => r1  upper_bound_check_0 => o1
//!     left_input_1 => a2  right_input_1 => b2  result_1 => r2  upper_bound_check_1 => o2
//!     left_input_2 => a3  right_input_2 => b3  result_2 => r3  upper_bound_check_2 => o3
//!
//!     field_overflow => x  
//!     result_carry_0 => y1  
//!     result_carry_1 => y2
//!     upper_bound_check_carry_0 => z1   
//!     upper_bound_check_carry_1 => z2   
//!
//!     max_sub_foreign_modulus_2 => k_3 = 2^88 - m_3
//!     max_sub_foreign_modulus_1 => k_2 = 2^88 - m_2 - 1
//!     max_sub_foreign_modulus_0 => k_1 = 2^88 - m_1 - 1
//!

use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{prologue::*, ConstantExpr::ForeignFieldModulus},
    gate::GateType,
};

/// Implementation of the ForeignFieldAdd gate
pub struct FFAdd<F>(PhantomData<F>);

impl<F> Argument<F> for FFAdd<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 11;

    fn constraints() -> Vec<E<F>> {
        let foreign_modulus_0 = E::constant(ForeignFieldModulus(0));
        let foreign_modulus_1 = E::constant(ForeignFieldModulus(1));
        let foreign_modulus_2 = E::constant(ForeignFieldModulus(2));

        let two_to_88 = constant(F::from(2u64).pow([88]));

        //   2^(2*88) * m_1 + 2^(88) * m_2 + m_3
        // + 2^(2*88) * k_1 + 2^(88) * k_2 + k_3
        // = 2^(3*88)
        // Assume that m_1 != 0, m_2 != 0, m_3 != 0 (otherwise overflows are annoying)
        // TODO: Assert this somewhere
        // => k_3 = 2^(88) - m_3
        // => k_2 = 2^(88) - m_2 - 1 (extra 1 comes from overflow of m_3 + k_3)
        // => k_1 = 2^(88) - m_1 - 1 (extra 1 comes from overflow of m_2 + k_2 + 1)
        let max_sub_foreign_modulus_2 = two_to_88.clone() - foreign_modulus_2.clone();
        let max_sub_foreign_modulus_1 = two_to_88.clone() - foreign_modulus_1.clone() - 1u64.into();
        let max_sub_foreign_modulus_0 = two_to_88.clone() - foreign_modulus_0.clone() - 1u64.into();

        let left_input_0 = witness_curr::<F>(0);
        let left_input_1 = witness_curr::<F>(1);
        let left_input_2 = witness_curr::<F>(2);

        let right_input_0 = witness_curr::<F>(3);
        let right_input_1 = witness_curr::<F>(4);
        let right_input_2 = witness_curr::<F>(5);

        let field_overflow = witness_curr::<F>(6);

        // Carry bits for limb overflows / underflows.
        let result_carry_0 = witness_curr::<F>(7);
        let result_carry_1 = witness_curr::<F>(8);

        let upper_bound_check_carry_0 = witness_curr::<F>(9);
        let upper_bound_check_carry_1 = witness_curr::<F>(10);

        let result_0 = witness_next::<F>(0);
        let result_1 = witness_next::<F>(1);
        let result_2 = witness_next::<F>(2);

        let upper_bound_check_0 = witness_next::<F>(3);
        let upper_bound_check_1 = witness_next::<F>(4);
        let upper_bound_check_2 = witness_next::<F>(5);

        let mut res = vec![
            // Field overflow bit is 0 or 1.
            field_overflow.clone() * (field_overflow.clone() - 1u64.into()),
            // Carry bits are -1, 0, or 1.
            result_carry_0.clone()
                * (result_carry_0.clone() - 1u64.into())
                * (result_carry_0.clone() + 1u64.into()),
            result_carry_1.clone()
                * (result_carry_1.clone() - 1u64.into())
                * (result_carry_1.clone() + 1u64.into()),
        ];

        // r_1 = a_1 + b_1 - x * m_1 + y_1
        let result_calculated_0 = left_input_0 + right_input_0
            - field_overflow.clone() * foreign_modulus_0
            + result_carry_0.clone();
        // r_2 = a_2 + b_2 - x * m_2 - 2^88 * y_1 + y_2
        let result_calculated_1 = left_input_1 + right_input_1
            - field_overflow.clone() * foreign_modulus_1
            - (result_carry_0 * two_to_88.clone())
            + result_carry_1.clone();
        // r_3 = a_3 + b_3 - x * m_3 - 2^88 * y_2
        let result_calculated_2 = left_input_2 + right_input_2
            - field_overflow * foreign_modulus_2
            - (result_carry_1 * two_to_88.clone());

        // Result values match
        res.push(result_0.clone() - result_calculated_0);
        res.push(result_1.clone() - result_calculated_1);
        res.push(result_2.clone() - result_calculated_2);

        // Upper bound check's carry bits are 0 or 1
        res.push(
            upper_bound_check_carry_0.clone() * (upper_bound_check_carry_0.clone() - 1u64.into()),
        );
        res.push(
            upper_bound_check_carry_1.clone() * (upper_bound_check_carry_1.clone() - 1u64.into()),
        );

        // o_1 = r_1 + k_1 + z_1
        let upper_bound_check_calculated_0 =
            result_0 + max_sub_foreign_modulus_0 + upper_bound_check_carry_0.clone();
        // o_2 = r_2 + k_2 - z_1 * 2^88 + z_2
        let upper_bound_check_calculated_1 = result_1 + max_sub_foreign_modulus_1
            - upper_bound_check_carry_0 * two_to_88.clone()
            - upper_bound_check_carry_1.clone();
        // o_3 = r_3 + k_3 - z_2 * 2^88
        let upper_bound_check_calculated_2 =
            result_2 + max_sub_foreign_modulus_2 - (upper_bound_check_carry_1 * two_to_88);

        // Upper bound values match
        res.push(upper_bound_check_0 - upper_bound_check_calculated_0);
        res.push(upper_bound_check_1 - upper_bound_check_calculated_1);
        res.push(upper_bound_check_2 - upper_bound_check_calculated_2);

        res
    }
}

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
