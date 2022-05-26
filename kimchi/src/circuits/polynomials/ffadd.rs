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

use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{prologue::*, ConstantExpr::ForeignFieldModulus},
    gate::GateType,
};

/// Implementation of the VarbaseMul gate
pub struct FFAdd<F>(PhantomData<F>);

impl<F> Argument<F> for FFAdd<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 21;

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

        let mut res = vec![];

        // Field overflow bit is 0 or 1.
        res.push(field_overflow.clone() * (field_overflow.clone() - 1u64.into()));

        // Carry bits are -1, 0, or 1.
        res.push(
            result_carry_0.clone()
                * (result_carry_0.clone() - 1u64.into())
                * (result_carry_0.clone() + 1u64.into()),
        );
        res.push(
            result_carry_1.clone()
                * (result_carry_1.clone() - 1u64.into())
                * (result_carry_1.clone() + 1u64.into()),
        );

        // r_1 = a_1 + b_1 - x * m_1 + y_1
        let result_calculated_0 = left_input_0.clone() + right_input_0.clone()
            - field_overflow.clone() * foreign_modulus_0.clone()
            + result_carry_0.clone();
        // r_2 = a_2 + b_2 - x * m_2 - 2^88 * y_1 + y_2
        let result_calculated_1 = left_input_1.clone() + right_input_1.clone()
            - field_overflow.clone() * foreign_modulus_1.clone()
            - (result_carry_0.clone() * two_to_88.clone())
            + result_carry_1.clone();
        // r_3 = a_3 + b_3 - x * m_3 - 2^88 * y_2
        let result_calculated_2 = left_input_2.clone() + right_input_2.clone()
            - field_overflow.clone() * foreign_modulus_2.clone()
            - (result_carry_1.clone() * two_to_88.clone());

        // Result values match
        res.push(result_0.clone() - result_calculated_0.clone());
        res.push(result_1.clone() - result_calculated_1.clone());
        res.push(result_2.clone() - result_calculated_2.clone());

        // Upper bound check's carry bits are 0 or 1
        res.push(
            upper_bound_check_carry_0.clone() * (upper_bound_check_carry_0.clone() - 1u64.into()),
        );
        res.push(
            upper_bound_check_carry_1.clone() * (upper_bound_check_carry_1.clone() - 1u64.into()),
        );

        // o_1 = r_1 + k_1 + z_1
        let upper_bound_check_calculated_0 =
            result_0.clone() + max_sub_foreign_modulus_0 + upper_bound_check_carry_0.clone();
        // o_2 = r_2 + k_2 - z_1 * 2^88 + z_2
        let upper_bound_check_calculated_1 = result_1.clone() + max_sub_foreign_modulus_1
            - upper_bound_check_carry_0.clone() * two_to_88.clone()
            - upper_bound_check_carry_1.clone();
        // o_3 = r_3 + k_3 - z_2 * 2^88
        let upper_bound_check_calculated_2 = result_2.clone() + max_sub_foreign_modulus_2
            - (upper_bound_check_carry_1.clone() * two_to_88.clone());

        // Upper bound values match
        res.push(upper_bound_check_0 - upper_bound_check_calculated_0);
        res.push(upper_bound_check_1 - upper_bound_check_calculated_1);
        res.push(upper_bound_check_2 - upper_bound_check_calculated_2);

        res
    }
}
