/// ForeignMul0 - Foreign field element constraints
///
///    Foreign field element F is comprised of three 88-bit limbs L0L1L2
///
///    * This circuit gate is used to partially constrain L0 and L1
///    * The rest of L0 and L1 are constrained by a single ForeignMul2
///    * This gate operates on the Curr row
///
/// It uses three different types of constraints
///   * plookup - plookup (12-bits)
///   * copy    - copy to another cell (12-bits)
///   * crumb   - degree-4 constraint (2-bits)
///
/// For limb L the layout looks like this
///
/// Column | Curr
///      0 | L
///      1 | plookup Lp0
///      2 | plookup Lp1
///      3 | plookup Lp2
///      4 | plookup Lp3
///      5 | copy Lp4
///      6 | copy Lp5
///      7 | crumb Lc0
///      8 | crumb Lc1
///      9 | crumb Lc2
///     10 | crumb Lc3
///     11 | crumb Lc4
///     12 | crumb Lc5
///     13 | crumb Lc6
///     14 | crumb Lc7
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, E},
    gate::GateType,
    polynomial::COLUMNS,
};
use ark_ff::{FftField, Zero};

#[derive(Default)]
pub struct ForeignMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul0);
    const CONSTRAINTS: u32 = 9;

    // Constraints for ForeignMul0
    //   * Operates on Curr row
    //   * Range constrain all sublimbs except p4 and p5 (barring plookup constraints, which are done elsewhere)
    //   * Constrain that combining all sublimbs equals the limb stored in column 0
    fn constraints() -> Vec<E<F>> {
        // Row structure
        //       0    1       ... 4       5    6    7     ... 14
        // Curr  limb plookup ... plookup copy copy crumb ... crumb

        // 1) Apply range constraints on sublimbs

        // Columns 1-4 are 12-bit plookup range constraints (these are specified elsewhere)

        // Create 8 2-bit chunk range constraints
        let mut constraints = (7..COLUMNS)
            .map(|i| crumb(&witness_curr(i)))
            .collect::<Vec<E<F>>>();

        // 2) Constrain that the combined sublimbs equals the limb stored in w(0) where
        //    limb = lp0 lp1 lp2 lp3 lp4 lp5 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7
        //    in big-endian byte order.
        //
        //          Columns
        //          0      1    2    3    4    5    6    7    8    9    10   11   12   13   14
        //    Curr  limb   lp0  lp1  lp2  lp3  lp4  lp5  lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  <- LSB
        //
        // Check limb =  lp0*2^0 + lp1*2^{12}  + ... + p5*2^{60}   + lc0*2^{72}  + lc1*2^{74}  + ... + lc7*2^{86}
        //       w(0) = w(1)*2^0 + w(2)*2^{12} + ... + w(6)*2^{60} + w(7)*2^{72} + w(8)*2^{74} + ... + w(14)*2^{86}
        //            = \sum i \in [1,7] 2^{12*(i - 1)}*w(i) + \sum i \in [8,14] 2^{2*(i - 7) + 6*12}*w(i)
        let combined_sublimbs = (1..8).fold(E::zero(), |acc, i| {
            // 12-bit chunk offset
            acc + E::<F>::from(2u64).pow(12 * (i as u64 - 1)) * witness_curr(i)
        }) + (8..COLUMNS).fold(E::zero(), |acc, i| {
            // 2-bit chunk offset
            acc + E::<F>::from(2u64).pow(2 * (i as u64 - 7) + 6 * 12) * witness_curr(i)
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - witness_curr(0));

        constraints
    }
}
