///```text
/// Foreign field multiplication circuit gates for native field $F_n$ and
/// foreign field $F_f$, where $F_n$ is the generic type parameter `F` in code below
/// and the foreign field modulus $f$ is store in the constraint system (`cs.formod_field_modulus`).
///
/// For more details please see: https://hackmd.io/37M7qiTaSIKaZjCC5OnM1w?view
///
/// Inputs:
///   * $a, b \in F_f$ := foreign field element multiplicands
///   * $f$ := foreign field modulus
///
/// Witness:
///   * $q, r \in F_f$ := foreign field quotient and remainder
///
/// Constraint: This gate is used to constrain that
///
///       $a \cdot b = q \cdot f + r$
///
///     in $F_f$ by using the native field $F_n$.
///
/// **Layout**
///
/// | Row(s) | Gate                | Checks                | Witness
/// -|-|-|-
///   0-3    | multi-range-check-0 | "                     | $a$
///   4-7    | multi-range-check-1 | "                     | $b$
///   8-11   | multi-range-check-2 | "                     | $q$
///   12-15  | multi-range-check-3 | "                     | $r$
///   16-19  | multi-range-check-4 | "                     | $p_{10}, p_{110}, v_{10}$
///   20     | ForeignFieldMul     | "                     | (see below)
///   21     | ForeignFieldMul1    | "                     | (see below)
///
use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, witness_next, ConstantExpr, E},
    gate::GateType,
};

/// ForeignFieldMul0
///    Rows: Curr + Next
#[derive(Default)]
pub struct ForeignFieldMul<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul);
    const CONSTRAINTS: u32 = 7;

    ///   | col | `ForeignFieldMul`   | `Zero`           |
    ///   | --- | ------------------- | ---------------- |
    ///   |   0 | `a_low` (copy)      | `a_top` (copy)   |
    ///   |   1 | `b_low` (copy)      | `b_top` (copy)   |
    ///   |   2 | `wit_sft` (look)    | `a_mid` (copy)   |
    ///   |   3 | `quo_sft` (look)    | `b_mid` (copy)   |
    ///   |   4 | `quo_top` (copy)    | `rem_top` (copy) |
    ///   |   5 | `quo_mid` (copy)    | `rem_mid` (copy) |
    ///   |   6 | `quo_low` (copy)    | `rem_low` (copy) |
    ///   |   7 | `mul_mid_top_carry` |                  |
    ///   |   8 | `mul_mid_top_limb`  |                  |
    ///   |   9 | `mul_mid_low`       |                  |
    ///   |  10 | `wit_top_carry`     |                  |
    ///   |  11 | `wit_top_limb`      |                  |
    ///   |  12 | `wit_low`           |                  |
    ///   |  13 |                     |                  |
    ///   |  14 |                     |                  |
    fn constraints() -> Vec<E<F>> {
        // WITNESS VALUES
        // witness values from the current and next rows according to the layout

        // -> define top, middle and lower limbs of the foreign field element `a`
        let a_top = witness_next(0);
        let a_mid = witness_next(2);
        let a_low = witness_curr(0);

        // -> define top, middle and lower limbs of the foreign field element `b`
        let b_top = witness_next(1);
        let b_mid = witness_next(3);
        let b_low = witness_curr(1);

        // -> define top, middle and lower limbs of the quotient and remainder
        let quo_top = witness_curr(4);
        let quo_mid = witness_curr(5);
        let quo_low = witness_curr(6);
        let rem_top = witness_next(4);
        let rem_mid = witness_next(5);
        let rem_low = witness_next(6);

        // -> define shifted values of the quotient and witness values
        let wit_sft = witness_curr(2);
        let quo_sft = witness_curr(3);

        // -> define decomposition values of the intermediate multiplication
        let mul_mid_top_carry = witness_curr(7);
        let mul_mid_top_limb = witness_curr(8);
        let mul_mid_low = witness_curr(9);

        // -> define witness values for the zero sum
        let wit_top_carry = witness_curr(10);
        let wit_top_limb = witness_curr(11);
        let wit_low = witness_curr(12);

        // AUXILIARY DEFINITIONS

        let mut constraints = vec![];

        // powers of 2 for range constraints
        let eight = E::from(8);
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(2).pow(9);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = two_to_88.clone().pow(2);

        // negated foreign field modulus in 3 limbs: top, middle and lower
        let neg_formod_top = -E::constant(ConstantExpr::ForeignFieldModulus(2));
        let neg_formod_mid = -E::constant(ConstantExpr::ForeignFieldModulus(1));
        let neg_formod_low = -E::constant(ConstantExpr::ForeignFieldModulus(0));

        // intermediate products for readability of the constraints
        //    p0 := a0 * b0 - q0 * f0
        //    p1 := a0 * b1 + a1 * b0 - q0 * f1 - q1 * f0
        //    p2 := a0 * b2 + a2 * b0 + a1 * b1 - q0 * f2 - q2 * f0 - q1 * f1
        let mul_low = a_low.clone() * b_low.clone() + quo_low.clone() * neg_formod_low.clone();
        let mul_mid = a_low.clone() * b_mid.clone()
            + a_mid.clone() * b_low.clone()
            + quo_low.clone() * neg_formod_mid.clone()
            + quo_mid.clone() * neg_formod_low.clone();
        let mul_top = a_low.clone() * b_top.clone()
            + a_top.clone() * b_low.clone()
            + a_mid.clone() * b_mid.clone()
            + quo_low.clone() * neg_formod_top.clone()
            + quo_top.clone() * neg_formod_low.clone()
            + quo_mid.clone() * neg_formod_mid.clone();

        // GATE CONSTRAINTS

        // 1) Constrain decomposition of middle intermediate product
        // p11 = 2^88 * p111 + p110
        // p1 = 2^88 * p11 + p10
        // 2^88 * (2^88 * cw(10) + cw(9)) + cw(7) = nw(0) * cw(0) + nw(4) * nw(5) - nw(1) * f1 - nw(6) * f0
        let mul_mid_top = two_to_88.clone() * mul_mid_top_carry.clone() + mul_mid_top_limb.clone();
        let mul_mid_sum = two_to_88.clone() * mul_mid_top + mul_mid_low.clone();
        constraints.push(mul_mid - mul_mid_sum.clone());

        // 2) Constrain carry witness value $v_0 \in [0, 2^2)$
        constraints.push(crumb(&wit_low.clone()));

        // 3) Constrain intermediate product fragment $p_{111} \in [0, 2^2)$
        constraints.push(crumb(&mul_mid_top_carry.clone()));

        // 4) Constrain $v_11$ value
        constraints.push(wit_sft - two_to_9 * wit_top_carry.clone());

        // 5) Constrain shifted $v_0$ witness value to prove $u_0$'s leading bits are zero
        //    2^176 * v0 = p0 - r0 + 2^88 ( p10 - r1 )
        //    2^176 * wc(11) = p0 + 2^88 * wc(7) - wc(4) - 2^88 * wc(5)
        let zero_low =
            mul_low - rem_low.clone() + two_to_88.clone() * (mul_mid_low.clone() - rem_mid.clone());
        constraints.push(zero_low - two_to_176 * wit_low.clone());

        // 6) Constraint shifted $v_1$ witness value to prove $u_1$'s bits are zero
        //    Let $v_1 = v_{10} + 2^{3} *  v_{11}$
        //    Check 2^88 * v1 = 2^88 * p111 + p110 + p2 - r2 + v0
        let wit_top = wit_top_limb.clone() + eight * wit_top_carry;
        let zero_top = wit_low + mul_mid_sum + mul_top.clone() - rem_top.clone();
        constraints.push(zero_top - two_to_88 * wit_top);

        // 7) Check zero prefix of quotient
        constraints.push(quo_sft - two_to_8 * quo_low);

        // The remaining constraints on next columns 2 and 3 are plookup constraints

        constraints
    }
}
