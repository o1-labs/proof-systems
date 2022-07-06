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

    fn constraints() -> Vec<E<F>> {
        // Columns: 0  1  2         3        4  5  6  7   8   9    10   11 12 13  14
        //    Curr: b0 b2 a2        q2       r0 r1 r2 p10     p110 p111 v0    v10 v11
        //    Next: a0 q0 2^9 * v11 2^8 * q0 a1 b1 q1

        let b0 = witness_curr(0);
        let b2 = witness_curr(1);
        let a2 = witness_curr(2);
        let q2 = witness_curr(3);
        let r0 = witness_curr(4);
        let r1 = witness_curr(5);
        let r2 = witness_curr(6);
        let p10 = witness_curr(7);
        //let p11 = witness_curr(8);
        let p110 = witness_curr(9);
        let p111 = witness_curr(10);
        let v0 = witness_curr(11);
        //let v1 = witness_curr(12);
        let v10 = witness_curr(13);
        let v11 = witness_curr(14);

        let a0 = witness_next(0);
        let q0 = witness_next(1);
        let v11_shift = witness_next(2);
        let q0_shift = witness_next(3);
        let a1 = witness_next(4);
        let b1 = witness_next(5);
        let q1 = witness_next(6);
        //let p0 = witness_next(7);
        //let p1 = witness_next(8);
        //let p2 = witness_next(9);

        let mut constraints = vec![];
        let eight = E::from(8);
        let two_to_8 = E::from(256);
        let two_to_9 = E::from(2).pow(9);
        let two_to_88 = E::from(2).pow(88);
        let two_to_176 = two_to_88.clone().pow(2);
        let neg_foreign_0 = -E::constant(ConstantExpr::ForeignFieldModulus(0));
        let neg_foreign_1 = -E::constant(ConstantExpr::ForeignFieldModulus(1));
        let neg_foreign_2 = -E::constant(ConstantExpr::ForeignFieldModulus(2));

        // 0) Define intermediate products for readability
        //    p0 := a0 * b0 - q0 * f0
        //    p1 := a0 * b1 + a1 * b0 - q0 * f1 - q1 * f0
        //    p2 := a0 * b2 + a2 * b0 + a1 * b1 - q0 * f2 - q2 * f0 - q1 * f1

        let low_prod = a0.clone() * b0.clone() + q0.clone() * neg_foreign_0.clone();
        let middle_prod = a0.clone() * b1.clone()
            + a1.clone() * b0.clone()
            + q0.clone() * neg_foreign_1.clone()
            + q1.clone() * neg_foreign_0.clone();
        let up_prod = a0.clone() * b2.clone()
            + a2.clone() * b0.clone()
            + a1.clone() * b1.clone()
            + q0.clone() * neg_foreign_2.clone()
            + q2.clone() * neg_foreign_0.clone()
            + q1.clone() * neg_foreign_1.clone();

        // 1) Constrain decomposition of middle intermediate product
        // p11 = 2^88 * p111 + p110
        // p1 = 2^88 * p11 + p10
        // 2^88 * (2^88 * cw(10) + cw(9)) + cw(7) = nw(0) * cw(0) + nw(4) * nw(5) - nw(1) * f1 - nw(6) * f0
        let middle_prod_prefix = two_to_88.clone() * p111.clone() + p110.clone();
        let middle_prod_sum = two_to_88.clone() * middle_prod_prefix + p10.clone();
        constraints.push(middle_prod - middle_prod_sum.clone());

        // 2) Constrain carry witness value $v_0 \in [0, 2^2)$
        constraints.push(crumb(&v0.clone()));

        // 3) Constrain intermediate product fragment $p_{111} \in [0, 2^2)$
        constraints.push(crumb(&p111.clone()));

        // 4) Constrain $v_11$ value
        constraints.push(v11_shift - two_to_9 * v11.clone());

        // 5) Constrain shifted $v_0$ witness value to prove $u_0$'s leading bits are zero
        //    2^176 * v0 = p0 - r0 + 2^88 ( p10 - r1 )
        //    2^176 * wc(11) = p0 + 2^88 * wc(7) - wc(4) - 2^88 * wc(5)
        let low_half = low_prod - r0.clone() + two_to_88.clone() * (p10.clone() - r1.clone());
        constraints.push(low_half - two_to_176 * v0.clone());

        //constraints.push(witness_curr(12) - v1_sum);

        // 6) Constraint shifted $v_1$ witness value to prove $u_1$'s bits are zero
        //    Let $v_1 = v_{10} + 2^{3} *  v_{11}$
        //    Check 2^88 * v1 = 2^88 * p111 + p110 + p2 - r2 + v0
        let v1_sum = v10.clone() + eight * v11;
        let up_half = v0 + middle_prod_sum + up_prod.clone() - r2.clone();
        constraints.push(up_half - two_to_88 * v1_sum);

        // 7) Check zero prefix of quotient
        constraints.push(two_to_8 * q0 - q0_shift);

        // The remaining constraints on next columns 2 and 3 are plookup constraints

        constraints
    }
}
