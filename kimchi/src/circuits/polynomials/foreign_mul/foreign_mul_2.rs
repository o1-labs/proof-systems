// ForeignMul2 - Foreign field element constraints
//
//     Foreign field element F is comprised of three 88-bit limbs L0L1L2
//
//     * This circuit gate is used to partially constrain L0 and L1
//     * Together with two instances of ForeignMul0 the limbs L0 and L1 are fully constrained
//     * It operates on the Curr row
//
// Column | Curr
//      0 | 0 (ignored)
//      1 | plookup L0p4
//      2 | plookup L0p5
//      3 | plookup L1p4
//      4 | plookup L1p5
//      5 | (ignored)
//      6 | (ignored)
//      7 | (ignored)
//      8 | (ignored)
//      9 | (ignored)
//     10 | (ignored)
//     11 | (ignored)
//     12 | (ignored)
//     13 | (ignored)
//     14 | (ignored)

use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{Column, E},
    gate::{CurrOrNext, GateType},
};
use ark_ff::FftField;
use CurrOrNext::*;

use super::constraints::sublimb_plookup_constraint;

#[derive(Default)]
pub struct ForeignMul2<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul2<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul2);
    const CONSTRAINTS: u32 = 5;

    // Constraints for ForeignMul2
    //   * Operates on Curr row
    //   * Range constrain sublimbs stored in columns 1 through 4
    //   * The contents of these cells are the 4 12-bit sublimbs that
    //     could not be plookup'ed in rows Curr - 3 and Curr - 2
    //   * Copy constraints are present (elsewhere) to make sure
    //     these cells are equal to those
    fn constraints() -> Vec<E<F>> {
        let w = |i| E::cell(Column::Witness(i), Curr);

        // Row structure
        //  Column w(i) 0    1       ... 4       5     6     7     ... 14
        //         Curr limb plookup ... plookup crumb crumb crumb ... crumb

        // Apply range constraints on sublimbs (create 4 12-bit plookup range constraints)
        // crumbs were constrained by ForeignMul1 circuit gate
        let mut constraints: Vec<E<F>> =
            (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect();

        // Temporary dummy constraint to avoid zero polynomial edge case
        // and avoid verifier check that all commitments aren't identically zero
        constraints.push(E::<F>::cell(
            Column::Index(GateType::Poseidon),
            CurrOrNext::Curr,
        ));

        constraints
    }
}
