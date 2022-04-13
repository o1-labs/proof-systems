// ForeignMul0 - Foreign field element constraints
//
//     Foreign field element F is comprised of three 88-bit limbs L0L1L2
//
//     * This circuit gate is used to partially constrain L0 or L1
//     * The rest of L0 and L1 are constrained by a single ForeignMul2
//     * It operates on the Curr row
//
// Column | Curr
//      0 | L
//      1 | plookup Lp0
//      2 | plookup Lp1
//      3 | plookup Lp2
//      4 | plookup Lp3
//      5 | copy Lp4
//      6 | copy Lp5
//      7 | crumb Lc0
//      8 | crumb Lc1
//      9 | crumb Lc2
//     10 | crumb Lc3
//     11 | crumb Lc4
//     12 | crumb Lc5
//     13 | crumb Lc6
//     14 | crumb Lc7

use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{Column, E},
    gate::{CurrOrNext, GateType},
    polynomial::COLUMNS,
};
use ark_ff::{FftField, Zero};
use CurrOrNext::*;

use super::constraints::{sublimb_plookup_constraint, two, sublimb_crumb_constraint};

#[derive(Default)]
pub struct ForeignMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul0);
    const CONSTRAINTS: u32 = 13;

    // Constraints for ForeignMul0
    //   * Operates on Curr row
    //   * Range constrain all sublimbs except p4 and p5
    //   * Constrain that combining all sublimbs equals the limb stored in column 0
    fn constraints() -> Vec<E<F>> {
        let w = |i| E::cell(Column::Witness(i), Curr);

        // Row structure
        //  Column w(i) 0    1       ... 4       5    6    7     ... 14
        //        Curr  limb plookup ... plookup copy copy crumb ... crumb

        // 1) Apply range constraints on sublimbs

        // Create 4 12-bit plookup range constraints
        let mut constraints: Vec<E<F>> =
            (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect();

        // Create 8 2-bit chunk range constraints
        constraints.append(
            &mut (7..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w(i)))
                .collect::<Vec<E<F>>>(),
        );

        // 2) Constrain that the combined sublimbs equals the limb stored in w(0) where
        //    limb = lp0 lp1 lp2 lp3 lp4 lp5 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7
        //    in big-endian byte order.
        //
        //     Columns
        //    R        0      1    2    3    4    5    6    7    8    9    10   11   12   13   14
        //    o  Curr  limb   lp0  lp1  lp2  lp3  lp4  lp5  lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  <- LSB
        //    w               76   64   52   40   28   16   14   12   10    8    6    4    2    0
        //    s
        //
        // Check limb =  lp0*2^0 + lp1*2^{12}  + ... + p5*2^{60}   + lc0*2^{72}  + lc1*2^{74}  + ... + lc7*2^{86}
        //       w(0) = w(1)*2^0 + w(2)*2^{12} + ... + w(6)*2^{60} + w(7)*2^{72} + w(8)*2^{74} + ... + w(14)*2^{86}
        //            = \sum i \in [1,7] 2^{12*(i - 1)}*w(i) + \sum i \in [8,14] 2^{2*(i - 7) + 6*12}*w(i)
        let combined_sublimbs = (1..COLUMNS).fold(E::zero(), |acc, i| {
            match i {
                1..=7 => {
                    // 12-bit chunk offset
                    acc + two().pow(12 * (i as u64 - 1)) * w(i)
                }
                8..=COLUMNS => {
                    // 2-bit chunk offset
                    acc + two().pow(2 * (i as u64 - 7) + 6 * 12) * w(i)
                }
                _ => {
                    panic!("Invalid column index {}", i)
                }
            }
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - w(0));

        constraints
    }
}
