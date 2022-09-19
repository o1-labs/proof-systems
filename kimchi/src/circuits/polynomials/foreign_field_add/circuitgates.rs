//! Foreign field addition gate.

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::boolean, prologue::*, ConstantExpr::ForeignFieldModulus},
    gate::GateType,
};
use ark_ff::FftField;
use o1_utils::foreign_field::LIMB_BITS;
use std::marker::PhantomData;

//~ These circuit gates are used to constrain that
//~
//~     $$left_input + right_input = field_overflow * foreign_modulus + result$$
//~
//~  Documentation:
//~
//~   For more details please see the [FFadd RFC](../rfcs/ffadd.md)
//~
//~   Mapping:
//~     To make things clearer, the following mapping between the variable names
//~     used in the code and those of the document can be helpful.
//~
//~ ```text
//~     left_input_lo -> a0  right_input_lo -> b0  result_lo -> r0  upper_bound_lo -> u0
//~     left_input_mi -> a1  right_input_mi -> b1  result_mi -> r1  upper_bound_mi -> u1
//~     left_input_hi -> a2  right_input_hi -> b2  result_hi -> r2  upper_bound_hi -> u2
//~
//~     field_overflow  -> x
//~     result_carry_lo -> c0
//~     result_carry_mi -> c1
//~
//~     upper_bound_carry_lo -> k0
//~     upper_bound_carry_mi -> k1
//~
//~     max_sub_foreign_modulus_lo -> g_0 = 2^88 - m_0
//~     max_sub_foreign_modulus_mi -> g_1 = 2^88 - m_1 - 1
//~     max_sub_foreign_modulus_hi -> g_2 = 2^88 - m_2 - 1
//~```
//~
//~ Let `left_input_lo`, `left_input_mi`, `left_input_hi` be 88-bit limbs of the left element
//~
//~ Let `right_input_lo`, `right_input_mi`, `right_input_hi` be 88-bit limbs of the right element
//~
//~ Let `foreign_modulus_lo`, `foreign_modulus_mi`, `foreign_modulus_hi` be 88-bit limbs of the foreign modulus
//~
//~ Then the limbs of the result are
//~
//~ - `result_lo = left_input_lo + right_input_lo - field_overflow * foreign_modulus_lo - 2^{88} * result_carry_lo`
//~ - `result_mi = left_input_mi + right_input_mi - field_overflow * foreign_modulus_mi - 2^{88} * result_carry_mi + result_carry_lo`
//~ - `result_hi = left_input_hi + right_input_hi - field_overflow * foreign_modulus_hi + result_carry_mi`
//~
//~ `field_overflow` $=0$ or $1$ handles overflows in the field
//~
//~ `result_carry_i` $= -1, 0, 1$ are auxiliary variables that handle carries between limbs
//~
//~ We need to do an additional range check to make sure that the result is less than the modulus, by
//~ adding `2^{3*88} - foreign_modulus`. (This can be computed easily from the limbs of the modulus)
//~ Represent this as limbs
//~ `max_sub_foreign_modulus_lo, max_sub_foreign_modulus_mi, max_sub_foreign_modulus_hi`.
//~
//~ The upper-bound check can be calculated as
//~ - `upper_bound_hi = result_hi + max_sub_foreign_modulus_hi + upper_bound_carry_mi`
//~ - `upper_bound_mi = result_mi + max_sub_foreign_modulus_mi - upper_bound_carry_mi * 2^{88} + upper_bound_carry_lo`
//~ - `upper_bound_lo = result_lo + max_sub_foreign_modulus_lo - upper_bound_carry_lo * 2^{88}`
//~
//~ `upper_bound_carry_i` $= 0$ or $1$ are auxiliary variables that handle carries between limbs
//~
//~ Then, range check `result` and `upper_bound`. The range check of `upper_bound` can be skipped if there are
//~ multiple additions and `result` is an intermediate value that is unused elsewhere (since the final `result`
//~ must have had the right number of moduluses subtracted along the way).
//~
//~ You could lay this out as a double-width gate, e.g.
//~
//~ | col | `FFAdd`                 | more `FFAdd`       | or `FFFin`         | `Zero`             |
//~ | --- | ----------------------- | ------------------ | ------------------ | ------------------ |
//~ |   0 | `left_input_lo` (copy)  | `result_lo` (copy) | `resmin_lo` (copy) | `bound_lo` (copy)  |
//~ |   1 | `left_input_mi` (copy)  | `result_mi` (copy) | `resmin_mi` (copy) | `bound_mi`  (copy) |
//~ |   2 | `left_input_hi` (copy)  | `result_hi` (copy) | `resmin_hi` (copy) | `bound_hi`  (copy) |
//~ |   3 | `right_input_lo` (copy) |  ...               |  0                 |
//~ |   4 | `right_input_mi` (copy) |  ...               |  0                 |
//~ |   5 | `right_input_hi` (copy) |  ...               |  2^88              |
//~ |   6 | `field_overflow`        |  ...               |  1                 |
//~ |   7 | `carry_lo`              |  ...               | `bound_carry_lo`   |
//~ |   8 | `carry_mi`              |  ...               | `bound_carry_mi`   |
//~ |   9 | `sign`                  |  ...               |  1                 |
//~ |  10 |                         |                    |                    |
//~ |  11 |                         |                    |                    |
//~ |  12 |                         |                    |                    |
//~ |  13 |                         |                    |                    |
//~ |  14 |                         |                    |                    |
//~
//~ The reason to have a FFFinal gate is to impose the relation, otherwise if 2^264 is the right input of an FFAdd gate,
//~ There is no way to check that the ovf and sign were correct, nor the actual operation used the corresponding witness.

/// Implementation of the ForeignFieldAddition gate
pub struct ForeignFieldAdd<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldAdd<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 7;

    fn constraints() -> Vec<E<F>> {
        let foreign_modulus_lo = E::constant(ForeignFieldModulus(0));
        let foreign_modulus_mi = E::constant(ForeignFieldModulus(1));
        let foreign_modulus_hi = E::constant(ForeignFieldModulus(2));

        let two_to_88 = constant(F::from(2u128.pow(LIMB_BITS as u32)));

        let left_input_lo = witness_curr::<F>(0);
        let left_input_mi = witness_curr::<F>(1);
        let left_input_hi = witness_curr::<F>(2);

        let right_input_lo = witness_curr::<F>(3);
        let right_input_mi = witness_curr::<F>(4);
        let right_input_hi = witness_curr::<F>(5);

        let field_overflow = witness_curr::<F>(6);

        // Result carry bits for limb overflows / underflows.
        let carry_lo = witness_curr::<F>(7);
        let carry_mi = witness_curr::<F>(8);

        let sign = witness_curr::<F>(9);

        let result_lo = witness_next::<F>(0);
        let result_mi = witness_next::<F>(1);
        let result_hi = witness_next::<F>(2);

        let mut res = vec![
            // Field overflow bit is 0 or s.
            field_overflow.clone() * (field_overflow.clone() - sign.clone()),
            // Carry bits are -1, 0, or 1.
            carry_lo.clone() * (carry_lo.clone() - 1u64.into()) * (carry_lo.clone() + 1u64.into()),
            carry_mi.clone() * (carry_mi.clone() - 1u64.into()) * (carry_mi.clone() + 1u64.into()),
            // Sign flag is 1 or -1
            (sign.clone() + 1u64.into()) * (sign.clone() - 1u64.into()),
        ];

        // r_0 = a_0 + s * b_0 - o * m_0 - 2^88 * c_0
        let result_calculated_lo = left_input_lo + sign.clone() * right_input_lo
            - field_overflow.clone() * foreign_modulus_lo.clone()
            - (carry_lo.clone() * two_to_88.clone());
        // r_1 = a_1 + s * b_1 - o * m_1 - 2^88 * c_1 + c_0
        let result_calculated_mi = left_input_mi + sign.clone() * right_input_mi
            - field_overflow.clone() * foreign_modulus_mi.clone()
            - (carry_mi.clone() * two_to_88.clone())
            + carry_lo;
        // r_2 = a_2 + s * b_2 - o * m_2 + c_1
        let result_calculated_hi = left_input_hi + sign * right_input_hi
            - field_overflow * foreign_modulus_hi.clone()
            + carry_mi;

        // Result values match
        res.push(result_lo.clone() - result_calculated_lo);
        res.push(result_mi.clone() - result_calculated_mi);
        res.push(result_hi.clone() - result_calculated_hi);

        res
    }
}

/// Implementation of the FFFin gate
pub struct ForeignFieldFin<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldFin<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldFin);
    const CONSTRAINTS: u32 = 7; // if not call FFAdd we could have less than in FFAdd

    fn constraints() -> Vec<E<F>> {
        // Perform a foreign field addition gate with these inputs
        // left_input_lo -> resmin_lo  right_input_lo -> 0     result_lo -> bound_lo  carry_lo -> bound_carry_lo
        // left_input_mi -> resmin_mi  right_input_mi -> 0     result_mi -> bound_mi  carry_mi -> bound_carry_mi
        // left_input_hi -> resmin_hi  right_input_hi -> 2^88  result_hi -> bound_hi
        // field_overflow -> 1         sign -> 1
        let mut res = ForeignFieldAdd::constraints();

        let foreign_modulus_lo = E::constant(ForeignFieldModulus(0));
        let foreign_modulus_mi = E::constant(ForeignFieldModulus(1));
        let foreign_modulus_hi = E::constant(ForeignFieldModulus(2));

        let right_lo = witness_curr::<F>(3);
        let right_mi = witness_curr::<F>(4);
        let right_hi = witness_curr::<F>(5);
        let field_overflow = witness_curr::<F>(6);
        //let bound_carry_lo = witness_curr::<F>(7);
        //let bound_carry_mi = witness_curr::<F>(8);

        // check that mod_mi nor mod_lo are zero
        let two_to_88 = constant(F::from(2u128.pow(LIMB_BITS as u32)));
        let max_sub_foreign_modulus_lo = two_to_88.clone() - foreign_modulus_lo.clone();
        let max_sub_foreign_modulus_mi =
            two_to_88.clone() - foreign_modulus_mi.clone() - 1u64.into();
        let max_sub_foreign_modulus_hi =
            two_to_88.clone() - foreign_modulus_hi.clone() - 1u64.into();

        //res.push(right_lo - max_sub_foreign_modulus_lo);
        //res.push(right_mi - max_sub_foreign_modulus_mi);
        //res.push(right_hi - max_sub_foreign_modulus_hi);

        //res.push(field_overflow - 1u64.into()); // ovf = 1
        // no need to check sign = 1 because redundant with above

        // Upper bound check`s carry bits are 0 or 1
        //res.push(boolean(&bound_carry_lo));
        //res.push(boolean(&bound_carry_mi));

        res

        /*
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


               // u_0 = r_0 + g_0 - k_0 * 2^88
               let upper_bound_calculated_lo = result_lo + max_sub_foreign_modulus_lo
                   - (upper_bound_carry_lo.clone() * two_to_88.clone());
               // u_1 = r_1 + g_1 - k_1 * 2^88 + k_0
               let upper_bound_calculated_mi = result_mi + max_sub_foreign_modulus_mi
                   - upper_bound_carry_mi.clone() * two_to_88
                   + upper_bound_carry_lo;
               // u_2 = r_2 + g_2 + k_1
               let upper_bound_calculated_hi =
                   result_hi + max_sub_foreign_modulus_hi + upper_bound_carry_mi;

        // Upper bound values match
        // u_0 = r_0 - f_0 - k_0 * 2^88
        // u_1 = r_1 - f_1 - k_1 * 2^88 + k0
        // u_2 = r_2 - f_2 + k_1
        res.push(
            bound_lo
                - (result_lo - foreign_modulus_lo - bound_carry_lo.clone() * two_to_88.clone()),
        );
        res.push(
            bound_mi
                - (result_mi - foreign_modulus_mi - bound_carry_mi.clone() * two_to_88.clone()
                    + bound_carry_lo),
        );
        res.push(
            bound_hi
                - (result_hi + two_to_88.clone() - foreign_modulus_hi + bound_carry_mi.clone()),
        );
        */
    }
}
