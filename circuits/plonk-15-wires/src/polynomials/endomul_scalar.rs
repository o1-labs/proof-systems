use crate::expr::{Cache, Column, E};
use crate::gate::{CircuitGate, CurrOrNext, GateType};
use crate::{nolookup::constraints::ConstraintSystem, wires::COLUMNS};
use ark_ff::{BitIteratorLE, FftField, Field, PrimeField, Zero};
use array_init::array_init;

impl<F: FftField> CircuitGate<F> {
    pub fn verify_endomul_scalar(
        &self,
        witness: &[Vec<F>; COLUMNS],
        _cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(
            self.typ,
            GateType::EndomulScalar,
            "incorrect gate type (should be EndomulScalar)"
        );

        let row = self.row;
        let n0 = witness[0][row];
        let n8 = witness[1][row];
        let a0 = witness[2][row];
        let b0 = witness[3][row];
        let a8 = witness[4][row];
        let b8 = witness[5][row];

        let xs: [_; 8] = array_init(|i| witness[6 + i][row]);

        let n8_expected = xs.iter().fold(n0, |acc, x| acc.double().double() + x);
        let a8_expected = xs.iter().fold(a0, |acc, x| acc.double() + c_func(*x));
        let b8_expected = xs.iter().fold(b0, |acc, x| acc.double() + d_func(*x));

        ensure_eq!(a8, a8_expected, "a8 incorrect");
        ensure_eq!(b8, b8_expected, "b8 incorrect");
        ensure_eq!(n8, n8_expected, "n8 incorrect");

        Ok(())
    }
}

fn polynomial<F: Field>(coeffs: &[F], x: &E<F>) -> E<F> {
    coeffs
        .iter()
        .rev()
        .fold(E::zero(), |acc, c| acc * x.clone() + E::literal(*c))
}

/// The constraint for the endomul scalar computation
///
/// Each row corresponds to 8 iterations of the inner loop in "algorithm 2" on page 29 of
/// [this paper](https://eprint.iacr.org/2019/1021.pdf).
///
/// The state of the algorithm that's updated across iterations of the loop is (a, b).
/// It's clear from that description of the algorithm that an iteration of the loop can
/// be written as
///
/// ```ignore
/// (a, b, i) ->
///   ( 2 * a + c_func(r_{2 * i}, r_{2 * i + 1}),
///     2 * b + d_func(r_{2 * i}, r_{2 * i + 1}) )
/// ```
///
/// for some functions c_func and d_func. If one works out what these functions are on
/// every input (thinking of a two bit input as a number in {0, 1, 2, 3}), one finds they
/// are given by
///
/// c_func(x), defined by
/// - c_func(0) = 0
/// - c_func(1) = 0
/// - c_func(2) = -1
/// - c_func(3) = 1
///
/// d_func(x), defined by
/// - d_func(0) = -1
/// - d_func(1) = 1
/// - d_func(2) = 0
/// - d_func(3) = 0
///
/// One can then interpolate to find polynomials that implement these functions on {0, 1, 2, 3}.
///
/// You can use sage, as
/// ```ignore
/// R = PolynomialRing(QQ, 'x')
/// c_func = R.lagrange_polynomial([(0, 0), (1, 0), (2, -1), (3, 1)])
/// d_func = R.lagrange_polynomial([(0, -1), (1, 1), (2, 0), (3, 0)])
/// ```
///
/// Then, c_func is given by
///
/// ```ignore
/// 2/3*x^3 - 5/2*x^2 + 11/6*x
/// ```
///
/// and d_func is given by
/// ```ignore
/// 2/3*x^3 - 7/2*x^2 + 29/6*x - 1 = c_func + (-x^2 + 3x - 1)
/// ```
///
/// We lay it out as
///
/// <pre>
/// 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14
/// n0   n8   a0   b0   a8   b8   x0   x1   x2   x3   x4   x5   x6   x7
/// </pre>
///
/// where each `xi` is a two bit "crumb".
///
/// We also use a polynomial to check that each `xi` is indeed in {0, 1, 2, 3},
///
/// ```ignore
/// crumb(x)
/// = x (x - 1) (x - 2) (x - 3)
/// = x^4 - 6*x^3 + 11*x^2 - 6*x
/// = x *(x^3 - 6*x^2 + 11*x - 6)
/// ```
pub fn constraint<F: Field>(alpha0: usize) -> E<F> {
    let curr_row = |c| E::cell(c, CurrOrNext::Curr);
    let witness_column = |i| curr_row(Column::Witness(i));

    let n0 = witness_column(0);
    let n8 = witness_column(1);
    let a0 = witness_column(2);
    let b0 = witness_column(3);
    let a8 = witness_column(4);
    let b8 = witness_column(5);

    let xs: [_; 8] = array_init(|i| witness_column(6 + i));

    let mut cache = Cache::new();

    let c_coeffs = [
        F::zero(),
        F::from(11u64) / F::from(6u64),
        -F::from(5u64) / F::from(2u64),
        F::from(2u64) / F::from(3u64),
    ];

    let crumb_over_x_coeffs = [-F::from(6u64), F::from(11u64), -F::from(6u64), F::one()];
    let crumb = |x: &E<F>| polynomial(&crumb_over_x_coeffs[..], x) * x.clone();
    let d_minus_c_coeffs = [-F::one(), F::from(3u64), -F::one()];

    let c_funcs: [_; 8] = array_init(|i| cache.cache(polynomial(&c_coeffs[..], &xs[i])));
    let d_funcs: [_; 8] =
        array_init(|i| c_funcs[i].clone() + polynomial(&d_minus_c_coeffs[..], &xs[i]));

    let n8_expected = xs
        .iter()
        .fold(n0, |acc, x| acc.double().double() + x.clone());

    // This is iterating
    //
    // a = 2 a + c
    // b = 2 b + d
    //
    // as in the paper.
    let a8_expected = c_funcs.iter().fold(a0, |acc, c| acc.double() + c.clone());
    let b8_expected = d_funcs.iter().fold(b0, |acc, d| acc.double() + d.clone());

    let mut constraints = vec![n8_expected - n8, a8_expected - a8, b8_expected - b8];
    constraints.extend(xs.iter().map(crumb));

    E::combine_constraints(alpha0, constraints) * curr_row(Column::Index(GateType::EndomulScalar))
}

pub fn witness<F: PrimeField + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    x: F,
    endo_scalar: F,
    num_bits: usize,
) -> F {
    let crumbs_per_row = 8;
    let bits_per_row = 2 * crumbs_per_row;
    assert_eq!(num_bits % bits_per_row, 0);

    let bits_lsb: Vec<_> = BitIteratorLE::new(x.into_repr()).take(num_bits).collect();
    let bits_msb: Vec<_> = bits_lsb.iter().rev().collect();

    let mut a = F::from(2u64);
    let mut b = F::from(2u64);
    let mut n = F::zero();

    let one = F::one();
    let neg_one = -one;

    for (i, row_bits) in bits_msb[..].chunks(bits_per_row).enumerate() {
        let row = row0 + i;
        w[0][row] = n;
        w[2][row] = a;
        w[3][row] = b;

        for (j, crumb_bits) in row_bits.chunks(2).enumerate() {
            let b0 = *crumb_bits[1];
            let b1 = *crumb_bits[0];

            let crumb = F::from(b0 as u64) + F::from(b1 as u64).double();
            w[6 + j][row] = crumb;

            a.double_in_place();
            b.double_in_place();

            let s = if b0 { &one } else { &neg_one };

            let a_prev = a;
            if !b1 {
                b += s;
            } else {
                a += s;
            }
            assert_eq!(a, a_prev + c_func(crumb));

            n.double_in_place().double_in_place();
            n += crumb;
        }

        w[1][row] = n;
        w[4][row] = a;
        w[5][row] = b;
    }

    assert_eq!(x, n);

    a * endo_scalar + b
}

fn c_func<F: Field>(x: F) -> F {
    if x == F::from(0u64) {
        F::zero()
    } else if x == F::from(1u64) {
        F::zero()
    } else if x == F::from(2u64) {
        -F::one()
    } else if x == F::from(3u64) {
        F::one()
    } else {
        panic!("c_func")
    }
}

fn d_func<F: Field>(x: F) -> F {
    if x == F::from(0u64) {
        -F::one()
    } else if x == F::from(1u64) {
        F::one()
    } else if x == F::from(2u64) {
        F::zero()
    } else if x == F::from(3u64) {
        F::zero()
    } else {
        panic!("c_func")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
    use mina_curves::pasta::fp::Fp as F;

    // 2/3*x^3 - 5/2*x^2 + 11/6*x
    fn c_poly(x: F) -> F {
        let x2 = x.square();
        let x3 = x * x2;
        (F::from(2u64) / F::from(3u64)) * x3 - (F::from(5u64) / F::from(2u64)) * x2
            + (F::from(11u64) / F::from(6u64)) * x
    }

    // -x^2 + 3x - 1
    fn d_minus_c_poly(x: F) -> F {
        let x2 = x.square();
        -F::one() * x2 + F::from(3u64) * x - F::one()
    }

    // Test equivalence of the "c function" in its lookup table,
    // logical, and polynomial forms.
    #[test]
    fn c_func_test() {
        let f1 = |x: F| c_func(x);

        let f2 = |x: F| -> F {
            let bits_le = x.into_repr().to_bits_le();
            let b0 = bits_le[0];
            let b1 = bits_le[1];

            if b1 {
                if b0 {
                    F::one()
                } else {
                    -F::one()
                }
            } else {
                F::zero()
            }
        };

        for x in 0u64..4u64 {
            let x = F::from(x);
            let y1 = f1(x);
            let y2 = f2(x);
            let y3 = c_poly(x);
            assert_eq!(y1, y2);
            assert_eq!(y2, y3);
        }
    }

    // Test equivalence of the "b function" in its lookup table,
    // logical, and polynomial forms.
    #[test]
    fn d_func_test() {
        let f1 = |x: F| d_func(x);

        let f2 = |x: F| -> F {
            let bits_le = x.into_repr().to_bits_le();
            let b0 = bits_le[0];
            let b1 = bits_le[1];

            if !b1 {
                if b0 {
                    F::one()
                } else {
                    -F::one()
                }
            } else {
                F::zero()
            }
        };

        for x in 0u64..4u64 {
            let x = F::from(x);
            let y1 = f1(x);
            let y2 = f2(x);
            let y3 = c_poly(x) + d_minus_c_poly(x);
            assert_eq!(y1, y2);
            assert_eq!(y2, y3);
        }
    }
}
