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
//    Each foreign field element a is decomposed into 3 88-bit limbs a = a0a1a2 such that
//      a0 = a0p0a0p1a0p2a0p3a0p4a0p5a0c0a0c1a0c2a0c3a0c4a0c5a0c6a0c7
//      a1 = a1p0a1p1a1p2a1p3a1p4a1p5a1c0a1c1a1c2a1c3a1c4a1c5a1c6a1c7
//      a2 = a2p0a2p1a2p2a2p3a2c0a2c1a2c2a2c3a2c4a2c5a2c6a2c7a2c8a2c9a2c10a2c11a2c12a2c13a2c14a2c15a2c16a2c17a2c18a2c19
//
//    where
//      * aXpi is a 12-bit sublimb of limb aX
//      * aXci is a 2-bit "crumb" limb of aX
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
//     * 12-bit sublimbs are constrainted with plookups
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
use std::fmt::{Formatter, Display};

use crate::expr::{Column, E, Expr, ConstantExpr, PolishToken, Cache};
use crate::gate::{CurrOrNext, GateType};
use crate::polynomial::COLUMNS;
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

fn cache<F: FftField>(mut x: E<F>) -> E<F> {
    CACHE.with(|cache| { x = cache.borrow_mut().cache(x.clone())} );
    x
}

// TODO: Cache or Lazy static
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
    sublimb.clone() * (sublimb.clone() - E::one()) * (sublimb.clone() - two()) * (sublimb.clone() - three())
}

// Constraints for ForeignMul0
//   * Operates on Curr row
//   * Range constrain all sublimbs except p4 and p5
//   * Constrain that combining all sublimbs equals the limb stored in column 0
fn foreign_mul0_constraints<F: FftField>(alpha: usize) -> E<F> {
    let w = |i| E::cell(Column::Witness(i), Curr);

    // Row structure
    //  Column w(i) 0    1       ... 4       5    6    7     ... 14
    //  Constraint  limb plookup ... plookup copy copy crumb ... crumb

    // 1) Constrain values of sublimbs

    // Create 12-bit plookup range constraints
    let mut constraints: Vec<E<F>> = (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect();

    // Create 2-bit chunk range constraints
    constraints.append(
        &mut (7..COLUMNS)
            .map(|i| sublimb_crumb_constraint(&w(i)))
            .collect::<Vec<E<F>>>(),
    );

    // 2) Constrain that the combined sublimbs equals the limb stored in w(0)

    // Check a0 = a0p0 a0p1 a0p2 a0p3 a0p4 a0p5 a0c0 a0c1 a0c2 a0c3 a0c4 a0c5 a0c6 a0c7 (little-endian byte order)
    // Column 0   1    2    3    4    5    6    7    8    9    10   11   12   13   14
    //     w(0) = a0p0*2^76 + a0p1*2^64 + ... + a0p4*2^28 + a0p5*2^16 + a0c0*2^14 + a0c1*2^12 + ... + a0c6*2^2 + a0c7*2^0
    //          = \sum i \in [1,6] 2^(12*(6 - i) + 16)*w(i) + \sum i \in [7,14] 2^(2*(14 - i))*w(i)
    let combined_sublimbs = (1..COLUMNS).fold(E::zero(), |acc, i| {
        match i {
            0 => {
                // ignore
                acc
            }
            1..=6 =>  {
                // 12-bit chunk
                acc + two().pow(12*(6 - i) + 16) * w(i)
            },
            7..=COLUMNS => {
                // 2-bit chunk
                acc + two().pow(2*(14 - i)) * w(i)
            },
            _ => {
                panic!("Invalid column index {}", i)
            }
        }
    });

    // w(0) = combined_sublimbs
    constraints.push(combined_sublimbs - w(0));

    E::combine_constraints(
        alpha,
        constraints,
    )
}

// Constraints for ForeignMul1
//   * Operates on Curr and Next row
//   * Range constrain all sublimbs
//   * Constrain that combining all sublimbs equals the limb stored in row Curr, column 0
fn foreign_mul1_constraints<F: FftField>(alpha: usize) -> E<F> {
    let w_curr = | i | E::cell(Column::Witness(i), Curr);
    let w_next = | i | E::cell(Column::Witness(i), Next);

    // Constraints structure
    //  Column      0    1       ... 4       5     ... 14
    //  Constraint  limb plookup ... plookup crumb ... crumb

    // Create 12-bit plookup range constraints
    let mut constraints: Vec<E<F>> = (1..5).map(|i| sublimb_plookup_constraint(&w_curr(i))).collect();

    // Create 2-bit chunk range constraints on Curr row
    constraints.append(
        &mut (5..15)
            .map(|i| sublimb_crumb_constraint(&w_curr(i)))
            .collect::<Vec<E<F>>>(),
    );

    // Create 2-bit chunk range constraints on Next row
    constraints.append(
        &mut (5..15)
        .map(|i| sublimb_crumb_constraint(&w_next(i)))
        .collect::<Vec<E<F>>>(),
    );

    E::combine_constraints(
        alpha,
        constraints,
    )
}

// Constraints for ForeignMul2
//   * Operates on Curr row
//   * Range constrain sublimbs stored in columns 1 through 4
//   * The contents of these cells are the 4 12-bit sublimbs that
//     could not be plooked-up in rows Curr - 3 and Curr - 2
//   * Copy constraints are present to make sure these cells
//     are equal to those
fn foreign_mul2_constraints<F: FftField>(alpha: usize) -> E<F> {
    E::combine_constraints(
        alpha,
        vec![],
    )
}

/// The constraints for foreign field multiplication
pub fn constraint<F: FftField>(alpha0: usize) -> E<F> {
    let index = |g: GateType| E::cell(Column::Index(g), Curr);
    vec![
        index(GateType::ForeignMul0) * foreign_mul0_constraints(alpha0),
        // index(GateType::ForeignMul1) * foreign_mul1_constraints(alpha1),
    ]
    .into_iter()
    .fold(E::zero(), |acc, x| acc + x)
}


#[cfg(test)]
mod tests {
    use crate::polynomials::foreign_mul;

    use ark_ec::{AffineCurve};
    use mina_curves::pasta::pallas;
    type PallasField = <pallas::Affine as AffineCurve>::BaseField;

    #[test]
    fn constraint() {
        let constraint = foreign_mul::constraint::<PallasField>(0);
        println!("constraint = {}", constraint);
    }
}
