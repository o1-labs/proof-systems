///```text
/// Foreign field multiplication circuit gates for native field $F_n$ and
/// foreign field $F_f$, where $F_n$ is the generic type parameter `F` in code below
/// and the foreign field modulus $f$ is store in the constraint system (`cs.foreign_field_modulus`).
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
/// | Row(s) | Gate type(s)       | Checks                | Bits | Witness
/// -|-|-|-
///   0-3    | multi-range-check  | "                     | 264  | $a$
///   4-7    | multi-range-check  | "                     | 264  | $b$
///   8-11   | multi-range-check  | "                     | 264  | $q$
///   12-15  | multi-range-check  | "                     | 264  | $r$
///   16-19  | multi-range-check  | "                     | 264  | $p_{10}, p_{111}, v_{10}$
///   20     | ForeignFieldMul0   | "                     | 3    | $v_{11} \in [0, 2^3)$
///   20     | ForeignFieldMul0   | "                     | 2    | $q[0][0] \in [0, 2^2)$ ($q < 2^{256}$)
///   20     | ForeignFieldMul0   | "                     | 2    | $p_{110} \in [0, 2^2)$
///   20     | ForeignFieldMul0   | "                     | 2    | $v_0 \in [0, 2^2)$
///   ?-?    | ForeignFieldMul    | Intermediate products |      | $p_0, p_1, p_2$
///   ?-?    | ForeignFieldMul    | Composition(s)        |      | $p_1[, p_0]$
///   ?-?    | ForeignFieldMul    | $u$-value halves      |      | $u_0, u_1$
///   ?-?    | ForeignFieldMul    | Assertions            |      | Equality checks
use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::E,
    gate::GateType,
};

#[derive(Default)]
pub struct ForeignFieldMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul0);
    const CONSTRAINTS: u32 = 0;

    fn constraints() -> Vec<E<F>> {
        /// Columns: 0    1       2  3      4    5 .. 14
        ///          q_0  p_{110} v  v_{11} v_0  (TODO: pack more in here)

    }
}
