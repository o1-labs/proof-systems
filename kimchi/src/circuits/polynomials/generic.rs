/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::circuits::gates::generic::{CONSTANT_COEFF, MUL_COEFF};
use crate::circuits::{
    expr::{Column, E},
    gate::{CurrOrNext, GateType},
};
use ark_ff::FftField;

pub fn constraint<F: FftField>() -> E<F> {
    let v = |c| E::cell(c, CurrOrNext::Curr);
    let w = |i| v(Column::Witness(i));
    v(Column::Index(GateType::Generic)) // Selector
        * (w(0) * v(Column::Coefficient(0)) // Left input
            + w(1) * v(Column::Coefficient(1)) // Right input
            + w(2) * v(Column::Coefficient(2)) // Output
            + w(0) * w(1) * v(Column::Coefficient(MUL_COEFF)) // Left input * right input
            + v(Column::Coefficient(CONSTANT_COEFF))) // Constant
}
