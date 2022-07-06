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
///   20     | ForeignFieldMul0    | "                     | (see below)
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
pub struct ForeignFieldMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul0);
    const CONSTRAINTS: u32 = 0; // TODO

    fn constraints() -> Vec<E<F>> {
        // Columns: 0  1  2         3        4  5  6  7   8   9    10   11 12 13  14
        //    Curr: b0 b2 a2        q2       r0 r1 r2 p10 p11 p110 p111 v0 v1 v10 v11
        //    Next: a0 q0 2^9 * v11 2^8 * q0 a1 b1 q1 p0  p1  p2
        let mut constraints = vec![];
        let two_to_88 = E::from(2).pow(88);
        // TODO: compute g0, g1, g2 instead (or negate things below)
        let foreign_modulus_0 = E::constant(ConstantExpr::ForeignFieldModulus(0));
        let foreign_modulus_1 = E::constant(ConstantExpr::ForeignFieldModulus(1));
        let foreign_modulus_2 = E::constant(ConstantExpr::ForeignFieldModulus(2));

        // 1) Constrain decomposition of middle intermediate product
        // 2^88 * (2^88 * p111 + p110) + p10 = a0 * b0 + a1 * b1 + q0 * g1 + q1 * g0
        // 2^88 * (2^88 * cw(10) + cw(9)) + cw(7) = nw(0) * cw(0) + nw(4) * nw(5) + nw(1) * g1 + nw(6) * g0
        let middle_intermediate_product_left = two_to_88.clone()
            * (two_to_88.clone() * witness_curr(10) + witness_curr(9))
            + witness_curr(7);
        let middle_intermediate_product_right = witness_next(0) * witness_curr(0)
            + witness_next(4) * witness_next(5)
            + witness_next(1) * foreign_modulus_1.clone()
            + witness_next(6) * foreign_modulus_0.clone();
        constraints.push(middle_intermediate_product_left - middle_intermediate_product_right);

        // 2) Constraint that $v_1 = v_{10} + 2^{3} *  v_{11}$
        //                    wc(12) = wc(13) + 2^{3} *  wc(14)
        let eight = E::from(8);
        let v1_sum = witness_curr(13) + eight * witness_curr(14);
        constraints.push(witness_curr(12) - v1_sum);

        // 3) Constrain carry witness value $v_0 \in [0, 2^2)$
        constraints.push(crumb(&witness_curr(11)));

        // 4) Constrain intermediate product fragment $p_{111} \in [0, 2^2)$
        constraints.push(crumb(&witness_curr(10)));

        // 5) Constrain $v_11$ value
        let two_to_9 = E::from(2).pow(9);
        constraints.push(two_to_9 * witness_curr(14) - witness_next(2));

        // 6) Constrain shifted $v_0$ witness value to prove $u_0$'s bits are zero
        //    Requires intermediate value p0 = a0 * b0 + q0 * g0
        //                                   = wn(0) * wc(0) + wn(1) * g0
        let p0 = witness_next(0) * witness_curr(0) + witness_next(1) * foreign_modulus_0;
        //    2^176 * v0 = p0 + 2^88 * p10 - r0 - 2^88 * r1
        //    2^176 * wc(11) = p0 + 2^88 * wc(7) - wc(4) - 2^88 * wc(5)
        let two_to_176 = E::from(2).pow(176);
        constraints.push(
            two_to_176 * witness_curr(11)
                - (p0 + two_to_88.clone() * witness_curr(7)
                    - witness_curr(4)
                    - two_to_88.clone() * witness_curr(5)),
        );

        // 7) Constraint shifted $v_1$ witness value to prove $u_1$'s bits are zero
        //    Requires intermediate value p2 = a0 * b2 + a2 * b0 + q0 * g2 + a1 * b1 + q1 * g1
        //                                    = nw(0) * cw(1) + cw(2) * cw(0) + nw(1) * g2 + nw(4) * nw(5) + nw(6) * g1
        let p2 = witness_next(0) * witness_curr(1)
            + witness_curr(2) * witness_curr(0)
            + witness_next(1) * foreign_modulus_2
            + witness_next(4) * witness_next(5)
            + witness_next(6) * foreign_modulus_1;
        // 2^88 * v1 = 2^88 * p111 + p110 + p2 - r2 + v0
        // 2^88 * cw(12) = 2^88 * cw(10) + p2 - cw(6) + cw(11)
        constraints.push(
            two_to_88.clone() * witness_curr(12)
                - (two_to_88 * witness_curr(10) + p2 - witness_curr(6) + witness_curr(11)),
        );

        constraints
    }
}

/// ForeignFieldMul1
///    Rows: Curr
#[derive(Default)]
pub struct ForeignFieldMul1<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul1<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul1);
    const CONSTRAINTS: u32 = 0; // TODO

    fn constraints() -> Vec<E<F>> {
        // Columns: 0  1  2         3        4  5  6  7   8   9    10   11 12 13  14
        //    Next: a0 q0 2^9 * v11 2^8 * q0 a1 b1 q1 p0  p1  p2
        let mut constraints = vec![];
        let two_to_8 = E::from(256);

        constraints.push(two_to_8 * witness_curr(1) - witness_curr(3));

        // The remaining constraints on columns 2 and 3 are plookup constraints

        constraints
    }
}
