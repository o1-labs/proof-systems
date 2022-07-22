///```text
/// This module implements foreign field addition.
///
///
/// let a_0, a_1, a_2 be 88-bit limbs of the left element
/// let b_0, b_1, b_2 be 88-bit limbs of the right element
/// let m_0, m_1, m_2 be 88-bit limbs of the modulus
///
/// Then the limbs of the result are
/// r_0 = a_0 + b_0 - o * m_0 - 2^88 * c_0
/// r_1 = a_1 + b_1 - o * m_1 - 2^88 * c_1 + c_0
/// r_2 = a_2 + b_2 - o * m_2 - 2^88 * ___ + c_1
///
/// o = 0 or 1 handles overflows in the field
/// c_i = -1, 0, 1 are auxiliary variables that handle carries between limbs
///
/// We need to do an additional range check to make sure that the result is < the modulus, by
/// adding 2^(3*88) - m. (This can be computed easily from the limbs of m.) Represent this as limbs
/// g_0, g_1, g_2.
/// The upper-bound check can be calculated as
/// u_2 = r_2 + g_2 + k_1
/// u_1 = r_1 + g_1 - k_1 * 2^88 + k_0
/// u_0 = r_0 + g_0 - k_0 * 2^88
///
/// k_i = 0 or 1 are auxiliary variables that handle carries between limbs
///
/// Then, range check r and o. The range check of o can be skipped if there are multiple additions
/// and r is an intermediate value that is unused elsewhere (since the final r must have had the
/// right number of moduluses subtracted along the way).
///
/// You could lay this out as a double-width gate, e.g.
/// a_0 a_1 a_2 b_0 b_1 b_2 o c_0 c_1 ___ k_0 k_1
/// r_0 r_1 r_2 u_0 u_1 u_2
///
///    | col | 'ForeignFieldAdd' | 'Zero'      |
///    | --- | ----------------- | ----------- |
///    |   0 | 'a0' (copy)       | 'r0' (copy) |
///    |   1 | 'a1' (copy)       | 'r1' (copy) |
///    |   2 | 'a2' (copy)       | 'r2' (copy) |
///    |   3 | 'b0' (copy)       | 'u0' (copy) |
///    |   4 | 'b1' (copy)       | 'u1' (copy) |
///    |   5 | 'b2' (copy)       | 'u2' (copy) |
///    |   6 | 'o'               |             |
///    |   7 | 'c0'              |             |
///    |   8 | 'c1'              |             |
///    |   9 | ´k0´              |             |
///    |  10 | 'k1'              |             |
///    |  11 |                   |             |
///    |  12 |                   |             |
///    |  13 |                   |             |
///    |  14 |                   |             |
///
///  Documentation:
///
///   For more details please see https://hackmd.io/7qnPOasqTTmElac8Xghnrw?view
///
///   Mapping:
///     To make things clearer, the following mapping between the variable names
///     used in the code and those of the document can be helpful.
///
///     left_input_lo -> a0  right_input_lo -> b0  result_lo -> r0  upper_bound_lo -> u0
///     left_input_mi -> a1  right_input_mi -> b1  result_mi -> r1  upper_bound_mi -> u1
///     left_input_hi -> a2  right_input_hi -> b2  result_hi -> r2  upper_bound_hi -> u2
///
///     field_overflow  -> o
///     result_carry_lo -> c0
///     result_carry_mi -> c1  
///
///     upper_bound_carry_lo -> k0   
///     upper_bound_carry_mi -> k1   
///
///     max_sub_foreign_modulus_lo -> g_0 = 2^88 - m_0
///     max_sub_foreign_modulus_mi -> g_1 = 2^88 - m_1 - 1
///     max_sub_foreign_modulus_hi -> g_2 = 2^88 - m_2 - 1
///```
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{prologue::*, ConstantExpr::ForeignFieldModulus},
    gate::GateType,
};

use ark_ff::FftField;
use o1_utils::foreign_field::LIMB_BITS;

/// Implementation of the ForeignFieldAdd gate
pub struct FFAdd<F>(PhantomData<F>);

impl<F> Argument<F> for FFAdd<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 11;

    fn constraints() -> Vec<E<F>> {
        let foreign_modulus_lo = E::constant(ForeignFieldModulus(0));
        let foreign_modulus_mi = E::constant(ForeignFieldModulus(1));
        let foreign_modulus_hi = E::constant(ForeignFieldModulus(2));

        let two_to_88 = constant(F::from(2u128.pow(LIMB_BITS)));

        //   2^(2*88) * m_2 + 2^(88) * m_1 + m_0
        // + 2^(2*88) * g_2 + 2^(88) * g_1 + g_0
        // = 2^(3*88)
        // Assume that m_0 != 0, m_1 != 0, m_2 != 0 (otherwise overflows are annoying)
        // TODO: Assert this somewhere
        // => g_0 = 2^(88) - m_0
        // => g_1 = 2^(88) - m_1 - 1 (extra 1 comes from overflow of m_0 + g_0)
        // => g_2 = 2^(88) - m_2 - 1 (extra 1 comes from overflow of m_1 + g_1 + 1)
        let max_sub_foreign_modulus_lo = two_to_88.clone() - foreign_modulus_lo.clone();
        let max_sub_foreign_modulus_mi =
            two_to_88.clone() - foreign_modulus_mi.clone() - 1u64.into();
        let max_sub_foreign_modulus_hi =
            two_to_88.clone() - foreign_modulus_hi.clone() - 1u64.into();

        let left_input_lo = witness_curr::<F>(0);
        let left_input_mi = witness_curr::<F>(1);
        let left_input_hi = witness_curr::<F>(2);

        let right_input_lo = witness_curr::<F>(3);
        let right_input_mi = witness_curr::<F>(4);
        let right_input_hi = witness_curr::<F>(5);

        let field_overflow = witness_curr::<F>(6);

        // Carry bits for limb overflows / underflows.
        let result_carry_lo = witness_curr::<F>(7);
        let result_carry_mi = witness_curr::<F>(8);

        let upper_bound_carry_lo = witness_curr::<F>(9);
        let upper_bound_carry_mi = witness_curr::<F>(10);

        let result_lo = witness_next::<F>(0);
        let result_mi = witness_next::<F>(1);
        let result_hi = witness_next::<F>(2);

        let upper_bound_lo = witness_next::<F>(3);
        let upper_bound_mi = witness_next::<F>(4);
        let upper_bound_hi = witness_next::<F>(5);

        let mut res = vec![
            // Field overflow bit is 0 or 1.
            field_overflow.clone() * (field_overflow.clone() - 1u64.into()),
            // Carry bits are -1, 0, or 1.
            result_carry_lo.clone()
                * (result_carry_lo.clone() - 1u64.into())
                * (result_carry_lo.clone() + 1u64.into()),
            result_carry_mi.clone()
                * (result_carry_mi.clone() - 1u64.into())
                * (result_carry_mi.clone() + 1u64.into()),
        ];

        // r_0 = a_0 + b_0 - o * m_0 - 2^88 * c_0
        let result_calculated_lo = left_input_lo + right_input_lo
            - field_overflow.clone() * foreign_modulus_lo
            - (result_carry_lo.clone() * two_to_88.clone());
        // r_1 = a_1 + b_1 - o * m_1 - 2^88 * c_1 + c_0
        let result_calculated_mi = left_input_mi + right_input_mi
            - field_overflow.clone() * foreign_modulus_mi
            - (result_carry_mi.clone() * two_to_88.clone())
            + result_carry_lo;
        // r_2 = a_2 + b_2 - o * m_2 - 2^88 * c_2 + c_1 // TODO: c_2
        let result_calculated_hi =
            left_input_hi + right_input_hi - field_overflow * foreign_modulus_hi + result_carry_mi;

        // Result values match
        res.push(result_lo.clone() - result_calculated_lo);
        res.push(result_mi.clone() - result_calculated_mi);
        res.push(result_hi.clone() - result_calculated_hi);

        // Upper bound check's carry bits are 0 or 1
        res.push(upper_bound_carry_lo.clone() * (upper_bound_carry_lo.clone() - 1u64.into()));
        res.push(upper_bound_carry_mi.clone() * (upper_bound_carry_mi.clone() - 1u64.into()));

        // u_0 = r_0 + g_0 - k_0 * 2^88
        let upper_bound_calculated_lo = result_lo + max_sub_foreign_modulus_lo
            - (upper_bound_carry_lo.clone() * two_to_88.clone());
        // u_1 = r_1 + g_1 - k_1 * 2^88 + k_0
        let upper_bound_calculated_mi = result_mi + max_sub_foreign_modulus_mi
            - upper_bound_carry_mi.clone() * two_to_88
            - upper_bound_carry_lo;
        // u_2 = r_2 + g_2 + k_1
        let upper_bound_calculated_hi =
            result_hi + max_sub_foreign_modulus_hi + upper_bound_carry_mi;

        // Upper bound values match
        res.push(upper_bound_lo - upper_bound_calculated_lo);
        res.push(upper_bound_mi - upper_bound_calculated_mi);
        res.push(upper_bound_hi - upper_bound_calculated_hi);

        res
    }
}
