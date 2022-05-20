///```text
/// Range check field element structure:
///
///    Each field element a should be decomposed into three 88-bit limbs a0, a1, a2 s.t. a = a0a1a2 in
///    little-endian byte order (i.e. a = a2*2^{2b} + a1*2^b + a0).
///
///    This gate only performs 3 88-bit range checks on a0, a1 and a2, but does not constrain that
///    the sum of those is equal to a.
///
///    L is a 12-bit lookup,
///    C is a 2-bit crumb.
///
///         <----6----> <------8------>
///    a0 = L L L L L L C C C C C C C C
///    a1 = L L L L L L C C C C C C C C
///         <--4--> <------------------20----------------->
///    a2 = L L L L C C C C C C C C C C C C C C C C C C C C
///
/// Input structure:
///
///   Each of the first 3 gates checks most of a different range-check input.
///   The final gate performs the remaining checks for all 3 inputs.
///
///   Row*  Contents**
///     0   a0
///     1   a1
///     2   a2
///     3   a0,a1,a2
///
///    (*)  Row offsets
///    (**) Some part of the limb is contained in this row
///
/// Constraints:
///
///   For efficiency, the field element inputs are constrained
///   by their sublimbs according to their type.
///    * 12-bit sublimbs are constrained with plookups
///    * 2-bit crumbs are constrained with degree-4 constraints
///
/// Example:
///
///  This example shows how input a is constrained
///
///   * aXpi is a 12-bit sublimb of limb aX
///   * aXci is a 2-bit "crumb" sublimb of aX
///
/// Gate:   RangeCheck0    RangeCheck0    RangeCheck1    RangeCheck2
///   Rows -->
///         0              1              2              3
///  C  0 | a0           | a1           | a2           | 0
///  o  1 | plookup a0p0 | plookup a1p0 | plookup a2p0 | plookup a0p4
///  l  2 | plookup a0p1 | plookup a1p1 | plookup a2p1 | plookup a0p5
///  s  3 | plookup a0p2 | plookup a1p2 | plookup a2p2 | plookup a1p4
///  |  4 | plookup a0p3 | plookup a1p3 | plookup a2p3 | plookup a1p5
/// \ / 5 | copy a0p4    | copy a1p4    | crumb a2c0   | crumb a2c10
///  '  6 | copy a0p5    | copy a1p5    | crumb a2c1   | crumb a2c11
///     7 | crumb a0c0   | crumb a1c0   | crumb a2c2   | crumb a2c12
///     8 | crumb a0c1   | crumb a1c1   | crumb a2c3   | crumb a2c13
///     9 | crumb a0c2   | crumb a1c2   | crumb a2c4   | crumb a2c14
///    10 | crumb a0c3   | crumb a1c3   | crumb a2c5   | crumb a2c15
///    11 | crumb a0c4   | crumb a1c4   | crumb a2c6   | crumb a2c16
///    12 | crumb a0c5   | crumb a1c5   | crumb a2c7   | crumb a2c17
///    13 | crumb a0c6   | crumb a1c6   | crumb a2c8   | crumb a2c18
///    14 | crumb a0c7   | crumb a1c7   | crumb a2c9   | crumb a2c19
///
///   The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
///   degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3).
///
///   Note that copy denotes a plookup that is deferred to the RangeCheck2 gate.
///   This is because of the limitation that we have at most 4 lookups per row.
///   The copies are constrained using the permutation argument.
///
/// Gate types:
///
///   Different rows are constrained differently using different CircuitGate types
///
///   Row   CircuitGate   Purpose
///     0   RangeCheck0   Partially constrain a0
///     1   RangeCheck0   Partially constrain a1
///     2   RangeCheck1   Fully constrain a2
///     3   RangeCheck2   Complete the constraining of a0 and a1
///
///  Nb. each CircuitGate type corresponds to a unique polynomial and thus
///       is assigned its own unique powers of alpha
///```
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{constraints::crumb, witness_curr, witness_next, E},
    gate::GateType,
    polynomial::COLUMNS,
};
use ark_ff::{FftField, One, Zero};

/// RangeCheck0 - Range check constraints
///
///    Field element F is comprised of three 88-bit limbs L0L1L2
///
///    * This circuit gate is used to partially constrain L0 and L1
///    * The rest of L0 and L1 are constrained by a single RangeCheck2
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

#[derive(Default)]
pub struct RangeCheck0<F>(PhantomData<F>);

impl<F> Argument<F> for RangeCheck0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::RangeCheck0);
    const CONSTRAINTS: u32 = 9;

    // Constraints for RangeCheck0
    //   * Operates on Curr row
    //   * Range constrain all sublimbs except p4 and p5 (barring plookup constraints, which are done elsewhere)
    //   * Constrain that combining all sublimbs equals the limb stored in column 0
    fn constraints() -> Vec<E<F>> {
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

        let mut power_of_2 = E::one();
        let mut sum_of_sublimbs = E::zero();

        // Sum 12-bit sublimbs
        for i in 1..7 {
            sum_of_sublimbs += power_of_2.clone() * witness_curr(i);
            power_of_2 *= 4096u64.into(); // 12 bits
        }

        // Sum 2-bit sublimbs
        for i in 7..COLUMNS {
            sum_of_sublimbs += power_of_2.clone() * witness_curr(i);
            power_of_2 *= 4u64.into(); // 2 bits
        }

        // Check limb against the sum of sublimbs
        constraints.push(sum_of_sublimbs - witness_curr(0));

        constraints
    }
}

/// RangeCheck1 - Range check constraints
///
///    Field element F is comprised of three 88-bit limbs L0L1L2
///
///    * This circuit gate is used to fully constrain L2
///    * It operates on the Curr and Next rows
///
/// It uses two different types of constraints
///   * plookup - plookup (12-bits)
///   * crumb   - degree-4 constraint (2-bits)
///
/// Column | Curr         | Next
///      0 | L2           | (ignored)
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

#[derive(Default)]
pub struct RangeCheck1<F>(PhantomData<F>);

impl<F> Argument<F> for RangeCheck1<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::RangeCheck1);
    const CONSTRAINTS: u32 = 21;

    // Constraints for RangeCheck1
    //   * Operates on Curr and Next row
    //   * Range constrain all sublimbs (barring plookup constraints, which are done elsewhere)
    //   * Constrain that combining all sublimbs equals the limb stored in row Curr, column 0
    fn constraints() -> Vec<E<F>> {
        // 1) Apply range constraints on sublimbs
        // Columns 1-4 are 12-bit plookup range constraints (these are specified elsewhere)

        // Create 10 2-bit chunk range constraints using Curr row
        let mut constraints = (5..COLUMNS)
            .map(|i| crumb(&witness_curr(i)))
            .collect::<Vec<E<F>>>();

        // Create 10 more 2-bit chunk range constraints using Next row
        constraints.append(
            &mut (5..COLUMNS)
                .map(|i| crumb(&witness_next(i)))
                .collect::<Vec<E<F>>>(),
        );

        // 2) Constrain that the combined sublimbs equals the limb l2 stored in w(0) where
        //    l2 = lp0 lp1 lp2 lp3 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7 lc8 lc9 lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //    in little-endian byte order.
        //
        //          Columns
        //          0    1   2   3   4   5    6    7    8    9    10   11   12   13   14
        //    Curr  l2   lp0 lp1 lp2 lp3 lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  lc8  lc9
        //    Next                       lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //
        // Check   l2 = lp0*2^0          + lp1*2^{12}       + ... + lp3*2^{36}       + lc0*2^{48}     + lc1*2^{50}     + ... + lc19*2^{66}
        //       w(0) = w_curr(1)*2^0    + w_curr(2)*2^{12} + ... + w_curr(4)*2^{36} + w_curr(5)*2^48 + w_curr(6)*2^50 + ... + w_curr(14)*2^66
        //            + w_next(5)*2^{68} + w_next(6)*2^{70} + ... + w_next(14)*2^{86}
        // (1st part) = \sum i \in [1,5] 2^{12*(i - 1)}*w_curr(i) + \sum i \in [6,14] 2^{2*(i - 5) + 4*12}*w_curr(i)
        // (2nd part) + \sum i \in [5,14] 2^{2*(i - 5} + 68)*w_next(i)

        let mut power_of_2 = E::one();
        let mut sum_of_sublimbs = E::zero();

        // 1st part: Sum 12-bit sublimbs (row Curr)
        for i in 1..5 {
            sum_of_sublimbs += power_of_2.clone() * witness_curr(i);
            power_of_2 *= 4096u64.into(); // 12 bits
        }

        // 1st part:  Sum 2-bit sublimbs (row Curr)
        for i in 5..COLUMNS {
            sum_of_sublimbs += power_of_2.clone() * witness_curr(i);
            power_of_2 *= 4u64.into(); // 2 bits
        }

        // 2nd part: Sum 2-bit sublimbs
        for i in 5..COLUMNS {
            sum_of_sublimbs += power_of_2.clone() * witness_next(i);
            power_of_2 *= 4u64.into(); // 2 bits
        }

        // Check limb against the sum of sublimbs
        constraints.push(sum_of_sublimbs - witness_curr(0));

        constraints
    }
}
