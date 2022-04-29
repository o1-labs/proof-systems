/// ForeignMul1 - Foreign field element constraints
///
///    Foreign field element F is comprised of three 88-bit limbs L0L1L2
///
///    * This circuit gate is used to fully constrain L2
///    * It operates on the Curr and Next rows
///
/// Column | Curr         | Next
///      0 | L2           | 0 (ignored)
///      1 | plookup L2p0 | (ignored)
///      2 | plookup L2p1 | (ignored)
///      3 | plookup L2p2 | (ignored)
///      4 | plookup L2p3 | (ignored)
///      5 | crumb L2c0   | crumb L2c10
///      6 | crumb L2c1   | crumb L2c11
///      7 | crumb L2c2   | crumb L2c12
///      8 | crumb L2c3   | crumb L2c13
///      9 | crumb L2c4   | crumb L2c14
///     10 | crumb L2c5   | crumb L2c15
///     11 | crumb L2c6   | crumb L2c16
///     12 | crumb L2c7   | crumb L2c17
///     13 | crumb L2c8   | crumb L2c18
///     14 | crumb L2c9   | crumb L2c19

use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{Column, E},
    gate::{CurrOrNext, GateType},
    polynomial::COLUMNS,
};
use ark_ff::{FftField, Zero};
use CurrOrNext::*;

use super::constraints::{sublimb_crumb_constraint, sublimb_plookup_constraint, two};

#[derive(Default)]
pub struct ForeignMul1<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul1<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul1);
    const CONSTRAINTS: u32 = 25;

    // Constraints for ForeignMul1
    //   * Operates on Curr and Next row
    //   * Range constrain all sublimbs
    //   * Constrain that combining all sublimbs equals the limb stored in row Curr, column 0
    fn constraints() -> Vec<E<F>> {
        let w_curr = |i| E::cell(Column::Witness(i), Curr);
        let w_next = |i| E::cell(Column::Witness(i), Next);

        // Constraints structure
        //  Column      0    1       ... 4       5     ... 14
        //        Curr  limb plookup ... plookup crumb ... crumb
        //        Next                           crumb ... crumb

        // 1) Apply range constraints on sublimbs

        // Create 4 12-bit plookup range constraints
        let mut constraints: Vec<E<F>> = (1..5)
            .map(|i| sublimb_plookup_constraint(&w_curr(i)))
            .collect();

        // Create 10 2-bit chunk range constraints using Curr row
        constraints.append(
            &mut (5..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w_curr(i)))
                .collect::<Vec<E<F>>>(),
        );

        // Create 10 more 2-bit chunk range constraints using Next row
        constraints.append(
            &mut (5..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w_next(i)))
                .collect::<Vec<E<F>>>(),
        );

        // 2) Constrain that the combined sublimbs equals the limb l2 stored in w(0) where
        //    l2 = lp0 lp1 lp2 lp3 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7 lc8 lc9 lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //    in little-endian byte order.
        //
        //     Columns
        //    R        0    1   2   3   4   5    6    7    8    9    10   11   12   13   14
        //    o  Curr  l2   lp0 lp1 lp2 lp3 lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  lc8  lc9
        //    w  Next                       lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //    s
        //
        // Check   l2 = lp0*2^0          + lp1*2^{12}       + ... + lp3*2^{36}       + lc0*2^{48}     + lc1*2^{50}     + ... + lc19*2^{66}
        //       w(0) = w_curr(1)*2^0    + w_curr(2)*2^{12} + ... + w_curr(4)*2^{36} + w_curr(5)*2^48 + w_curr(6)*2^50 + ... + w_curr(14)*2^66
        //            + w_next(5)*2^{68} + w_next(6)*2^{70} + ... + w_next(14)*2^{86}
        // (1st part) = \sum i \in [1,5] 2^{12*(i - 1)}*w_curr(i) + \sum i \in [6,14] 2^{2*(i - 5) + 4*12}*w_curr(i)
        // (2nd part) + \sum i \in [5,14] 2^{2*(i - 5} + 68)*w_next(i)

        // 1st part (Curr row): \sum i \in [1,5] 2^{12*(i - 1)}*w_curr(i) + \sum i \in [6,14] 2^{2*(i - 5) + 4*12}*w_curr(i)
        let combined_sublimbs = (1..COLUMNS).fold(E::zero(), |acc, i| {
            match i as usize {
                1..=4 => {
                    // 12-bit chunk
                    acc + two().pow(12 * (i as u64 - 1)) * w_curr(i)
                }
                5..=COLUMNS => {
                    // 2-bit chunk
                    acc + two().pow(2 * (i as u64 - 5) + 4 * 12) * w_curr(i)
                }
                _ => {
                    panic!("Invalid column index {}", i)
                }
            }
        });

        // 2nd part (Next row): \sum i \in [5,14] 2^{2*(i - 5) + 68}*w_next(i)
        let combined_sublimbs = (5..COLUMNS).fold(combined_sublimbs, |acc, i| {
            // 2-bit chunk
            acc + two().pow(2 * (i as u64 - 5) + 68) * w_next(i)
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - w_curr(0));

        constraints
    }
}
