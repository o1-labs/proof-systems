//! This implements a complete EC addition gate.
//! The layout is
//!
//! 0   1   2   3   4   5   6   7      8   9      10      11   12   13   14
//! x1  y1  x2  y2  x3  y3  inf same_x s   inf_z  x21_inv
//!
//! where
//! - `(x1, y1), (x2, y2)` are the inputs and `(x3, y3)` the output.
//! - `inf` is a boolean that is true iff the result (x3, y3) is the point at infinity.
//! The rest of the values are inaccessible from the permutation argument, but
//! - `same_x` is a boolean that is true iff `x1 == x2`.
use crate::expr::{Cache, Column, E};
use crate::gate::{CircuitGate, CurrOrNext, GateType};
use crate::wires::COLUMNS;
use ark_ff::{FftField, Field, One};
use CurrOrNext::*;

/// This enforces that
///
/// r = (z == 0) ? 1 : 0
///
/// Additionally, if r == 0, then z_inv = 1 / z.
///
/// If r == 1 however (i.e., if z == 0), then z_inv is unconstrained.
fn zero_check<F: Field>(z: E<F>, z_inv: E<F>, r: E<F>) -> Vec<E<F>> {
    vec![z_inv * z.clone() - (E::one() - r.clone()), r * z]
}

/// This function uses the constraints
///
///   (x2 - x1) * s = y2 - y1
///   s^2 = x1 + x2 + x3
///   y3 = s (x1 - x3) - y1
///
/// for addition and
///
///   2 * s * y1 = 3 * x1^2
///   s^2 = 2 x1 + x3
///   y3 = s (x1 - x3) - y1
///
/// for doubling.
///
/// See [here](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law) for the formulas used.
pub fn constraint<F: Field>(alpha0: usize) -> (usize, E<F>) {
    // This function makes 2 + 1 + 1 + 1 + 2 = 7 constraints
    let v = |c| E::cell(c, Curr);
    let w = |i| v(Column::Witness(i));

    let x1 = w(0);
    let y1 = w(1);
    let x2 = w(2);
    let y2 = w(3);
    let x3 = w(4);
    let y3 = w(5);

    let inf = w(6);
    // same_x is 1 if x1 == x2, 0 otherwise
    let same_x = w(7);

    let s = w(8);

    // This variable is used to constrain inf
    let inf_z = w(9);

    // This variable is used to constrain same_x
    let x21_inv = w(10);

    let mut cache = Cache::default();

    let x21 = cache.cache(x2.clone() - x1.clone());
    let y21 = cache.cache(y2 - y1.clone());

    // same_x is now constrained
    let mut res = zero_check(x21.clone(), x21_inv, same_x.clone());

    // this constrains s so that
    // if same_x:
    //   2 * s * y1 = 3 * x1^2
    // else:
    //   (x2 - x1) * s = y2 - y1
    {
        let x1_squared = cache.cache(x1.clone() * x1.clone());
        let dbl_case = s.clone().double() * y1.clone() - x1_squared.clone().double() - x1_squared;
        let add_case = x21 * s.clone() - y21.clone();

        res.push(same_x.clone() * dbl_case + (E::one() - same_x.clone()) * add_case);
    }

    // Unconditionally constrain
    //
    // s^2 = x1 + x2 + x3
    //
    // This constrains x3.
    res.push(x1.clone() + x2 + x3.clone() - s.clone() * s.clone());

    // Unconditionally constrain
    // y3 = -y1 + s(x1 - x3)
    //
    // This constrains y3.
    res.push(s * (x1 - x3) - y1 - y3);

    // It only remains to constrain inf
    //
    // The result is the point at infinity only if x1 == x2 but y1 != y2. I.e.,
    //
    // inf = same_x && !(y1 == y2)
    //
    // We can do this using a modified version of the zero_check constraints
    //
    // Let Y = (y1 == y2).
    //
    // The zero_check constraints for Y (introducing a new z_inv variable) would be
    //
    // (y2 - y1) Y = 0
    // (y2 - y1) z_inv = 1 - Y
    //
    // By definition,
    //
    // inf = same_x * (1 - Y) = same_x - Y same_x
    //
    // rearranging gives
    //
    // Y same_x = same_x - inf
    //
    // so multiplying the above constraints through by same_x yields constraints on inf.
    //
    // (y2 - y1) same_x Y = 0
    // (y2 - y1) same_x z_inv = inf
    //
    // i.e.,
    //
    // (y2 - y1) (same_x - inf) = 0
    // (y2 - y1) same_x z_inv = inf
    //
    // Now, since z_inv was an arbitrary variable, unused elsewhere, we'll set
    // inf_z to take on the value of same_x * z_inv, and thus we have equations
    //
    // (y2 - y1) (same_x - inf) = 0
    // (y2 - y1) inf_z = inf
    //
    // Let's check that these equations are correct.
    //
    // Case 1: [y1 == y2]
    //   In this case the expected result is inf = 0, since for the result to be the point at
    //   infinity we need y1 = -y2 (note here we assume y1 != 0, which is the case for prime order
    //   curves).
    //
    //   y2 - y1 = 0, so the second equation becomes inf = 0, which is correct.
    //
    //   We can set inf_z = 0 in this case.
    //
    // Case 2: [y1 != y2]
    //   In this case, the expected result is 1 if x1 == x2, and 0 if x1 != x2.
    //   I.e., inf = same_x.
    //
    //   y2 - y1 != 0, so the first equation implies same_x - inf = 0.
    //   I.e., inf = same_x, as desired.
    //
    //   In this case, we set
    //   inf_z = if same_x then 1 / (y2 - y1) else 0

    res.push(y21.clone() * (same_x - inf.clone()));
    res.push(y21 * inf_z - inf);

    (
        res.len(),
        v(Column::Index(GateType::CompleteAdd)) * E::combine_constraints(alpha0, res),
    )
}

impl<F: FftField> CircuitGate<F> {
    /// Check the correctness of witness values for a complete-add gate.
    pub fn verify_complete_add(&self, witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        let row = self.row;
        let x1 = witness[0][row];
        let y1 = witness[1][row];
        let x2 = witness[2][row];
        let y2 = witness[3][row];
        let x3 = witness[4][row];
        let y3 = witness[5][row];
        let inf = witness[6][row];
        let same_x = witness[7][row];
        let s = witness[8][row];
        let inf_z = witness[9][row];
        let x21_inv = witness[10][row];

        if x1 == x2 {
            ensure_eq!(same_x, F::one(), "Expected same_x = true");
        } else {
            ensure_eq!(same_x, F::zero(), "Expected same_x = false");
        }

        if same_x == F::one() {
            let x1_squared = x1.square();
            ensure_eq!(
                (s + s) * y1,
                (x1_squared.double() + x1_squared),
                "double s wrong"
            );
        } else {
            ensure_eq!((x2 - x1) * s, y2 - y1, "add s wrong");
        }

        ensure_eq!(s.square(), x1 + x2 + x3, "x3 wrong");
        let expected_y3 = s * (x1 - x3) - y1;
        ensure_eq!(
            y3,
            expected_y3,
            format!("y3 wrong {}: (expected {}, got {})", row, expected_y3, y3)
        );

        let not_same_y = F::from((y1 != y2) as u64);
        ensure_eq!(inf, same_x * not_same_y, "inf wrong");

        if y1 == y2 {
            ensure_eq!(inf_z, F::zero(), "wrong inf z (y1 == y2)");
        } else {
            let a = if same_x == F::one() {
                (y2 - y1).inverse().unwrap()
            } else {
                F::zero()
            };
            ensure_eq!(inf_z, a, "wrong inf z (y1 != y2)");
        }

        if x1 == x2 {
            ensure_eq!(x21_inv, F::zero(), "wrong x21_inv (x1 == x2)");
        } else {
            ensure_eq!(
                x21_inv,
                (x2 - x1).inverse().unwrap(),
                "wrong x21_inv (x1 != x2)"
            );
        }

        Ok(())
    }
}
