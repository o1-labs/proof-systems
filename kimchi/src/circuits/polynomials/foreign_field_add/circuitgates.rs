//! Foreign field addition gate.

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::constraints::ExprOps,
    gate::GateType,
};
use ark_ff::FftField;
use o1_utils::{foreign_field::LIMB_BITS, LIMB_COUNT};
use std::{array, marker::PhantomData};

//~ These circuit gates are used to constrain that
//~
//~ ```text
//~ left_input +/- right_input = field_overflow * foreign_modulus + result
//~```
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
//~     left_input_lo -> a0  right_input_lo -> b0  result_lo -> r0  bound_lo -> u0
//~     left_input_mi -> a1  right_input_mi -> b1  result_mi -> r1  bound_mi -> u1
//~     left_input_hi -> a2  right_input_hi -> b2  result_hi -> r2  bound_hi -> u2
//~
//~     field_overflow  -> q
//~     sign            -> s
//~     carry_lo        -> c0
//~     carry_mi        -> c1
//~     bound_carry_lo  -> k0
//~     bound_carry_mi  -> k1
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
//~ - `result_lo = left_input_lo +/- right_input_lo - field_overflow * foreign_modulus_lo - 2^{88} * result_carry_lo`
//~ - `result_mi = left_input_mi +/- right_input_mi - field_overflow * foreign_modulus_mi - 2^{88} * result_carry_mi + result_carry_lo`
//~ - `result_hi = left_input_hi +/- right_input_hi - field_overflow * foreign_modulus_hi + result_carry_mi`
//~
//~ `field_overflow` $=0$ or $1$ or $-1$ handles overflows in the field
//~
//~ `result_carry_i` $= -1, 0, 1$ are auxiliary variables that handle carries between limbs
//~
//~ Apart from the range checks of the chained inputs, we need to do an additional range check for a final bound
//~ to make sure that the result is less than the modulus, by adding `2^{3*88} - foreign_modulus` to it.
//~ (This can be computed easily from the limbs of the modulus)
//~ Note that `2^{264}` as limbs represents: (0, 0, 0, 1) then:
//~
//~ The upper-bound check can be calculated as
//~ - `bound_lo = result_lo - foreign_modulus_lo - bound_carry_lo * 2^{88}`
//~ - `bound_mi = result_mi - foreign_modulus_mi - bound_carry_mi * 2^{88} + bound_carry_lo`
//~ - `bound_hi = result_hi - foreign_modulus_hi + 2^{88} + bound_carry_mi`
//~
//~ `bound_carry_i` $= 0$ or $1$ or $-1$ are auxiliary variables that handle carries between limbs
//~
//~ The range check of `bound` can be skipped until the end of the operations
//~ and `result` is an intermediate value that is unused elsewhere (since the final `result`
//~ must have had the right number of moduli subtracted along the way).
//~
//~ You could lay this out as a double-width gate for chained foreign additions and a final row, e.g.
//~
//~ | col | `ForeignFieldAdd`       | more `ForeignFieldAdd` | or `ForeignFieldFin` |
//~ | --- | ----------------------- | ---------------------- | -------------------- |
//~ |   0 | `left_input_lo`  (copy) | `result_lo` (copy)     | `resmin_lo` (copy)   |
//~ |   1 | `left_input_mi`  (copy) | `result_mi` (copy)     | `resmin_mi` (copy)   |
//~ |   2 | `left_input_hi`  (copy) | `result_hi` (copy)     | `resmin_hi` (copy)   |
//~ |   3 | `right_input_lo` (copy) |  ...                   | `bound_lo`  (copy)   |
//~ |   4 | `right_input_mi` (copy) |  ...                   | `bound_mi`  (copy)   |
//~ |   5 | `right_input_hi` (copy) |  ...                   | `bound_hi`  (copy)   |
//~ |   6 | `field_overflow`        |  ...                   |  -                   |
//~ |   7 | `carry_lo`              |  ...                   | `bound_carry_lo`     |
//~ |   8 | `carry_mi`              |  ...                   | `bound_carry_mi`     |
//~ |   9 | `sign`                  |  ...                   |  -                   |
//~ |  10 |                         |                        |                      |
//~ |  11 |                         |                        |                      |
//~ |  12 |                         |                        |                      |
//~ |  13 |                         |                        |                      |
//~ |  14 |                         |                        |                      |
//~
//~ Having a specific final row that checks the bound is useful as it checks the upper bound
//~ without reusing the same constraints in the `ForeignFieldAdd` rows (which would require
//~ some extra constraints to be added to the circuit).

/// Implementation of the ForeignFieldAddition gate
pub struct ForeignFieldAdd<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldAdd<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldAdd);
    const CONSTRAINTS: u32 = 7;

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let field_overflow = env.witness_curr(6);
        let sign = env.witness_curr(9);

        let mut checks = vec![
            // Field overflow bit is 0 or s.
            field_overflow.clone() * (field_overflow - sign.clone()),
            // Sign flag is 1 or -1
            (sign.clone() + T::one()) * (sign - T::one()),
        ];

        // Carry bits are -1, 0, or 1.
        checks.append(&mut carry(env));

        // Result values match
        checks.append(&mut result(env));

        checks
    }
}

/// Implementation of the FFFin gate
pub struct ForeignFieldFin<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldFin<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldFin);
    const CONSTRAINTS: u32 = 5;

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // Similar to performing a foreign field addition gate with these inputs
        // left_input_lo -> resmin_lo  right_input_lo -> 0     result_lo -> bound_lo  carry_lo -> bound_carry_lo
        // left_input_mi -> resmin_mi  right_input_mi -> 0     result_mi -> bound_mi  carry_mi -> bound_carry_mi
        // left_input_hi -> resmin_hi  right_input_hi -> 2^88  result_hi -> bound_hi
        // field_overflow -> 1         sign -> 1

        // check addition for bound was performed correctly

        let resmin_lo = env.witness_curr(0);
        let resmin_mi = env.witness_curr(1);
        let resmin_hi = env.witness_curr(2);

        let bound_lo = env.witness_curr(3);
        let bound_mi = env.witness_curr(4);
        let bound_hi = env.witness_curr(5);

        let carry_lo = env.witness_curr(7);
        let carry_mi = env.witness_curr(8);

        let modulus: [T; LIMB_COUNT] = array::from_fn(|i| env.foreign_modulus(i));
        let two_to_limb = T::literal(F::from(2u128.pow(LIMB_BITS as u32)));

        // check values of carry bits
        let mut checks = carry(env);

        let computed_bound_lo =
            resmin_lo - modulus[0].clone() - carry_lo.clone() * two_to_limb.clone();
        let computed_bound_mi =
            resmin_mi - modulus[1].clone() - carry_mi.clone() * two_to_limb.clone() + carry_lo;
        let computed_bound_hi = resmin_hi - modulus[2].clone() + carry_mi + two_to_limb;

        checks.push(bound_lo - computed_bound_lo);
        checks.push(bound_mi - computed_bound_mi);
        checks.push(bound_hi - computed_bound_hi);
        checks
    }
}

/// Auxiliary function to obtain the constraints of a foreign field addition result
fn result<F: FftField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
    let foreign_modulus: [T; LIMB_COUNT] = array::from_fn(|i| env.foreign_modulus(i));

    let two_to_limb = T::literal(F::from(2u128.pow(LIMB_BITS as u32)));

    let left_input_lo = env.witness_curr(0);
    let left_input_mi = env.witness_curr(1);
    let left_input_hi = env.witness_curr(2);

    let right_input_lo = env.witness_curr(3);
    let right_input_mi = env.witness_curr(4);
    let right_input_hi = env.witness_curr(5);

    let field_overflow = env.witness_curr(6);

    // Result carry bits for limb overflows / underflows.
    let carry_lo = env.witness_curr(7);
    let carry_mi = env.witness_curr(8);

    let sign = env.witness_curr(9);

    let result_lo = env.witness_next(0);
    let result_mi = env.witness_next(1);
    let result_hi = env.witness_next(2);

    // r_0 = a_0 + s * b_0 - q * f_0 - 2^88 * c_0
    let result_calculated_lo = left_input_lo + sign.clone() * right_input_lo
        - field_overflow.clone() * foreign_modulus[0].clone()
        - carry_lo.clone() * two_to_limb.clone();
    // r_1 = a_1 + s * b_1 - q * f_1 - 2^88 * c_1 + c_0
    let result_calculated_mi = left_input_mi + sign.clone() * right_input_mi
        - field_overflow.clone() * foreign_modulus[1].clone()
        - carry_mi.clone() * two_to_limb
        + carry_lo;
    // r_2 = a_2 + s * b_2 - q * f_2 + c_1
    let result_calculated_hi = left_input_hi + sign * right_input_hi
        - field_overflow * foreign_modulus[2].clone()
        + carry_mi;

    // Result values match
    vec![
        result_lo - result_calculated_lo,
        result_mi - result_calculated_mi,
        result_hi - result_calculated_hi,
    ]
}

/// Auxiliary function to obtain the constraints to check the carry bits
fn carry<F: FftField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
    // Result carry bits for limb overflows / underflows.
    let carry_lo = env.witness_curr(7);
    let carry_mi = env.witness_curr(8);
    vec![
        // Carry bits are -1, 0, or 1.
        carry_lo.clone() * (carry_lo.clone() - T::one()) * (carry_lo + T::one()),
        carry_mi.clone() * (carry_mi.clone() - T::one()) * (carry_mi + T::one()),
    ]
}
