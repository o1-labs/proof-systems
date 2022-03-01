// Foreign field multiplication
//
// https://hackmd.io/XZUHHGpDQsSOs0dUGugB5w
//
// Globals:
//     * n: native field modulus
//     * p: foreign field modulus
//
// Inputs:
//     * a: left foreign field element operand a \in Fp
//     * b: right foreign field element operand b \in Fp
//
// Witness:
//     * q: \in Fp
//     * r: such that a*b = q*p +r
//
// Foreign field element structure:
//
//    Each foreign field element a is decomposed into three 88-bit limbs a0, a1, a2 s.t. a = a0a1a2 in
//    little-endian byte order (i.e. a = a2*2^{2b} + a1*2^b + a0)
//      a0 = a0p0a0p1a0p2a0p3a0p4a0p5a0c0a0c1a0c2a0c3a0c4a0c5a0c6a0c7
//      a1 = a1p0a1p1a1p2a1p3a1p4a1p5a1c0a1c1a1c2a1c3a1c4a1c5a1c6a1c7
//      a2 = a2p0a2p1a2p2a2p3a2c0a2c1a2c2a2c3a2c4a2c5a2c6a2c7a2c8a2c9a2c10a2c11a2c12a2c13a2c14a2c15a2c16a2c17a2c18a2c19
//
//    where
//      * aXpi is a 12-bit sublimb of limb aX
//      * aXci is a 2-bit "crumb" sublimb of aX
//
// Input structure:
//
//   Row*  Contents**
//     0   a0
//     1   a1
//     2   a2
//     3   a0,a1,a2
//     4   b0
//     5   b1
//     6   b2
//     7   b0,b1,b2
//
//    (*)  Row offsets
//    (**) Some part of the limb is contained in this row
//
// Constraints:
//
//   For efficiency, the foreign field element inputs are constrained
//   by their sublimbs according to their type.
//     * 12-bit sublimbs are constrained with plookups
//     * 2-bit crumbs are constrained with degree-4 constraints
//
// Example:
//
//   This example shows how input a is constrained
//
//          Rows -->
//          0              1              2              3
//   C  0 | a0           | a1             a2
//   o  1 | plookup a0p0 | plookup a1p0 | plookup a2p0 | plookup a0p4
//   l  2 | plookup a0p1 | plookup a1p1 | plookup a2p1 | plookup a0p5
//   s  3 | plookup a0p2 | plookup a1p2 | plookup a2p2 | plookup a1p4
//   |  4 | plookup a0p3 | plookup a1p3 | plookup a2p3 | plookup a1p5
//  \ / 5 | copy a0p4    | copy a1p4    | crumb a2c0   | crumb a2c10
//   '  6 | copy a0p5    | copy a1p5    | crumb a2c1   | crumb a2c11
//      7 | crumb a0c0   | crumb a1c0   | crumb a2c2   | crumb a2c12
//      8 | crumb a0c1   | crumb a1c1   | crumb a2c3   | crumb a2c13
//      9 | crumb a0c2   | crumb a1c2   | crumb a2c4   | crumb a2c14
//     10 | crumb a0c3   | crumb a1c3   | crumb a2c5   | crumb a2c15
//     11 | crumb a0c4   | crumb a1c4   | crumb a2c6   | crumb a2c16
//     12 | crumb a0c5   | crumb a1c5   | crumb a2c7   | crumb a2c17
//     13 | crumb a0c6   | crumb a1c6   | crumb a2c8   | crumb a2c18
//     14 | crumb a0c7   | crumb a1c7   | crumb a2c9   | crumb a2c19
//
//          ForeignMul0    ForeignMul0    ForeignMul1    ForeignMul2  <-- Gate type of row
//
//    The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
//    degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3)
//
// Gate types:
//
//   Different rows are constrained differently using different CircuitGate types
//
//   Row   CircuitGate   Purpose
//     0   ForeignMul0   Constrain a
//     1   ForeignMul0       "
//     2   ForeignMul1       "
//     3   ForeignMul2       "
//     4   ForeignMul0   Constrain b
//     5   ForeignMul0       "
//     6   ForeignMul1       "
//     7   ForeignMul2       "
//
//   Nb. each CircuitGate type corresponds to a unique polynomial and thus
//        is assigned its own unique powers of alpha

use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::{
    expr::{Cache, Column, ConstantExpr, Expr, PolishToken, E},
    gate::{CurrOrNext, GateType},
    polynomial::COLUMNS,
};

use ark_ff::{FftField, One, Zero};
use CurrOrNext::*;

struct Polish<F>(Vec<PolishToken<F>>);
impl<F: FftField> Display for Polish<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for x in self.0.iter() {
            match x {
                PolishToken::Literal(a) => write!(f, "{}, ", a)?,
                PolishToken::Add => write!(f, "+, ")?,
                PolishToken::Mul => write!(f, "*, ")?,
                PolishToken::Sub => write!(f, "-, ")?,
                x => write!(f, "{:?}, ", x)?,
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

thread_local! {
    static CACHE: std::cell::RefCell<Cache>  = RefCell::new(Cache::default());
}

fn _cache<F: FftField>(mut x: E<F>) -> E<F> {
    CACHE.with(|cache| x = cache.borrow_mut().cache(x.clone()));
    x
}

fn two<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u32.into()))
}

fn three<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(3u32.into()))
}

fn sublimb_plookup_constraint<F: FftField>(_sublimb: &E<F>) -> E<F> {
    // TODO: implement plookup constraint for 12-bit sublimb
    E::zero()
}

// Crumb constraint for 2-bit sublimb
fn sublimb_crumb_constraint<F: FftField>(sublimb: &E<F>) -> E<F> {
    // Assert sublimb \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
    sublimb.clone()
        * (sublimb.clone() - E::one())
        * (sublimb.clone() - two())
        * (sublimb.clone() - three())
}

pub fn get_circuit_gates() -> Vec<GateType> {
    vec![
        GateType::ForeignMul0,
        GateType::ForeignMul1,
        GateType::ForeignMul2,
    ]
}

pub fn circuit_gate_combined_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::ForeignMul0 => ForeignMul0::combined_constraints(alphas),
        GateType::ForeignMul1 => ForeignMul1::combined_constraints(alphas),
        GateType::ForeignMul2 => ForeignMul2::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

pub fn gate_combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    ForeignMul0::combined_constraints(alphas)
        + ForeignMul1::combined_constraints(alphas)
        + ForeignMul2::combined_constraints(alphas)
}

#[derive(Default)]
pub struct ForeignMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul0);
    const CONSTRAINTS: usize = 13;

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
                0 => {
                    // ignore
                    acc
                }
                1..=7 => {
                    // 12-bit chunk offset
                    acc + two().pow(12 * (i - 1)) * w(i)
                }
                8..=COLUMNS => {
                    // 2-bit chunk offset
                    acc + two().pow(2 * (i - 7) + 6 * 12) * w(i)
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

#[derive(Default)]
pub struct ForeignMul1<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul1<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul1);
    const CONSTRAINTS: usize = 25;

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
            match i {
                0 => {
                    // ignore
                    acc
                }
                1..=4 => {
                    // 12-bit chunk
                    acc + two().pow(12 * (i - 1)) * w_curr(i)
                }
                5..=COLUMNS => {
                    // 2-bit chunk
                    acc + two().pow(2 * (i - 5) + 4 * 12) * w_curr(i)
                }
                _ => {
                    panic!("Invalid column index {}", i)
                }
            }
        });

        // 2nd part (Next row): \sum i \in [5,14] 2^{2*(i - 5) + 68}*w_next(i)
        let combined_sublimbs = (5..COLUMNS).fold(combined_sublimbs, |acc, i| {
            // 2-bit chunk
            acc + two().pow(2 * (i - 5) + 68) * w_next(i)
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - w_curr(0));

        constraints
    }
}

#[derive(Default)]
pub struct ForeignMul2<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul2<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul2);
    const CONSTRAINTS: usize = 25;

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
        (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect()
    }
}
