///```text
/// Foreign field multiplication circuit gates for native field $F_n$ and
/// foreign field $F_f$, where $F_n$ is the generic type parameter `F` in code below
/// and the foreign field modulus $f$ is store in the constraint system (`cs.foreign_field_modulus`).
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
/// | Row(s) | Gate                | Witness
/// -|-|-
///   0-3    | multi-range-check-0 | $a$
///   4-7    | multi-range-check-1 | $b$
///   8-11   | multi-range-check-2 | $quotient$
///   12-15  | multi-range-check-3 | $remainder$
///   16-19  | multi-range-check-4 | $p_{10}, p_{110}, carry_{10}$
///   20     | ForeignFieldMul     | (see below)
///   21     | Zero                | (see below)
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

    fn constraints() -> Vec<E<F>> {
        // Columns | Curr           | Next
        // -|-|-
        //       0 | b0             | a0
        //       1 | b2             | quotient0
        //       2 | a2             | 2^9 * carry1_1
        //       3 | quotient2      | 2^8 * quotient0
        //       4 | remainder0     | a1
        //       5 | remainder1     | b1
        //       6 | remainder2     | quotient1
        //       7 | product_mid0   | (unused)
        //       8 | product_mid1_0 | (unused)
        //       9 | product_mid1_1 | (unused)
        //      10 | carry0         | (unused)
        //      11 | carry1_0       | (unused)
        //      12 | carry1_1       | (unused)

        // For clarity, load the Curr row variables into well-named variables
        let b0 = witness_curr(0);
        let b2 = witness_curr(1);
        let a2 = witness_curr(2);
        let quotient2 = witness_curr(3);
        let remainder0 = witness_curr(4);
        let remainder1 = witness_curr(5);
        let remainder2 = witness_curr(6);
        let product_mid0 = witness_curr(7);
        let product_mid1_0 = witness_curr(9);
        let product_mid1_1 = witness_curr(10);
        let carry0 = witness_curr(11);
        let carry1_0 = witness_curr(13);
        let carry1_1 = witness_curr(14);

        let a0 = witness_next(0);
        let quotient0 = witness_next(1);
        let carry1_1_shift = witness_next(2);
        let quotient0_shift = witness_next(3);
        let a1 = witness_next(4);
        let b1 = witness_next(5);
        let quotient1 = witness_next(6);

        let mut constraints = vec![];
        let eight = E::from(8);
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(512);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = two_to_88.clone().pow(2);
        let foreign_modulus0 = E::constant(ConstantExpr::ForeignFieldModulus(0));
        let foreign_modulus1 = E::constant(ConstantExpr::ForeignFieldModulus(1));
        let foreign_modulus2 = E::constant(ConstantExpr::ForeignFieldModulus(1));

        // 0) Define intermediate products for readability
        //    product_low := a0 * b0 - quotient0 * foreign_modulus0
        let product_low = a0.clone() * b0.clone() - quotient0.clone() * foreign_modulus0.clone();
        //    product_mid := a0 * b1 + a1 * b0 - quotient0 * foreign_modulus1 - quotient1 * foreign_modulus0
        let product_mid = a0.clone() * b1.clone()
            + a1.clone() * b0.clone()
            - quotient0.clone() * foreign_modulus1.clone()
            - quotient1.clone() * foreign_modulus0.clone();
        //    product_hi := a0 * b2 + a2 * b0 + a1 * b1 - quotient0 * foreign_modulus2 - quotient2 * foreign_modulus0 - quotient1 * foreign_modulus1
        let product_hi = a0 * b2
            + a2 * b0
            + a1 * b1
            - quotient0.clone() * foreign_modulus2
            - quotient2 * foreign_modulus0
            - quotient1 * foreign_modulus1;

        // 1) Constrain decomposition of middle intermediate product
        // p11 = 2^88 * product_mid1_1 + product_mid1_0
        // p1 = 2^88 * p11 + product_mid0
        // 2^88 * (2^88 * cw(10) + cw(9)) + cw(7) = nw(0) * cw(0) + nw(4) * nw(5) - nw(1) * foreign_modulus1 - nw(6) * foreign_modulus0
        let product_mid_prefix = two_to_88.clone() * product_mid1_1.clone() + product_mid1_0;
        let product_mid_sum = two_to_88.clone() * product_mid_prefix + product_mid0.clone();
        constraints.push(product_mid - product_mid_sum.clone());

        // 2) Constrain carry witness value $carry_0 \in [0, 2^2)$
        constraints.push(crumb(&carry0));

        // 3) Constrain intermediate product fragment $p_{111} \in [0, 2^2)$
        constraints.push(crumb(&product_mid1_1));

        // 4) Constrain $v_11$ value
        constraints.push(carry1_1_shift - two_to_9 * carry1_1.clone());

        // 5) Constrain shifted $carry_0$ witness value to prove $u_0$'s leading bits are zero
        //    2^176 * carry0 = p0 - remainder0 + 2^88 ( product_mid0 - remainder1 )
        //    2^176 * wc(11) = p0 + 2^88 * wc(7) - wc(4) - 2^88 * wc(5)
        let low_half = product_low - remainder0 + two_to_88.clone() * (product_mid0 - remainder1);
        constraints.push(low_half - two_to_176 * carry0.clone());

        // 6) Constraint shifted $v_1$ witness value to prove $u_1$'s bits are zero
        //    Let $v_1 = v_{10} + 2^{3} *  carry_{11}$
        //    Check 2^88 * v1 = 2^88 * product_mid1_1 + product_mid1_0 + p2 - remainder2 + carry0
        let carry1_sum = carry1_0 + eight * carry1_1;
        let up_half = carry0 + product_mid_sum + product_hi - remainder2;
        constraints.push(up_half - two_to_88 * carry1_sum);

        // 7) Check zero prefix of quotient
        constraints.push(two_to_8 * quotient0 - quotient0_shift);

        // 8-9) Plookups on the Next row @ columns 2 and 3
        constraints
    }
}
