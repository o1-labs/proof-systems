use crate::gate::{CircuitGate, GateType, CurrOrNext};
use crate::{
    nolookup::constraints::ConstraintSystem,
    wires::{GateWires, COLUMNS},
};
use ark_ff::{Field, One, Zero, FftField, PrimeField, BitIteratorLE};
use array_init::array_init;
use crate::expr::{E, Column, Cache};

impl<F: FftField> CircuitGate<F> {
    pub fn verify_endomul_scalar(
        &self,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// The constraint for the endomul scalar computation
///
/// We lay it out as 
///
///    0    1    2    3    4    5    6    7    8    9    10   11   12   13   14
///    n0   n8   a0   b0   a8   b8   x0   x1   x2   x3   x4   x5   x6   x7
///
/// We use several functions obtained by lagrange interpolation:
///
/// nybble(x) 
/// = x (x - 1) (x - 2) (x - 3)
/// = x^4 - 6*x^3 + 11*x^2 - 6*x
/// = x *(x^3 - 6*x^2 + 11*x - 6)
///
/// which checks that a value is a nybble.
///
/// a_func(x), defined by
/// - a_func(0) = 0
/// - a_func(1) = 0
/// - a_func(2) = -1
/// - a_func(3) = 1
///
/// and given by 2/3*x^3 - 5/2*x^2 + 11/6*x
///
/// b_func(x), defined by
/// - b_func(0) = -1
/// - b_func(1) = 1
/// - b_func(2) = 0
/// - b_func(3) = 0
///
/// and given by 2/3*x^3 - 7/2*x^2 + 29/6*x - 1 = a_func + (-x^2 + 3x - 1)
///
pub fn constraint<F: Field>(alpha0: usize) -> E<F> {
    let v = |c| E::cell(c, CurrOrNext::Curr);
    let w = |i| v(Column::Witness(i));

    let n0 = w(0);
    let n8 = w(1);
    let a0 = w(2);
    let b0 = w(3);
    let a8 = w(4);
    let b8 = w(5);

    let xs : [_; 8] = array_init(|i| w(6 + i));

    let mut cache = Cache::new();

    let polynomial = |coeffs: &[F], x: &E<F>| -> E<F> {
        coeffs.iter().rev().fold(
            E::zero(), |acc, c| acc * x.clone() + E::literal(*c))
    };

    let a_coeffs = [
        F::zero(),
        F::from(11u64) / F::from(6u64),
        -F::from(5u64) / F::from(2u64),
        F::from(2u64) / F::from(3u64)
    ];

    let nybble_over_x_coeffs = [ -F::from(6u64), F::from(11u64), -F::from(6u64), F::one() ];
    let nybble = |x: &E<F>| polynomial(&nybble_over_x_coeffs[..], x) * x.clone();
    let b_minus_a_coeffs = [ -F::one(), F::from(3u64), -F::one() ];

    let a_funcs : [_; 8] = array_init(|i| cache.cache(polynomial(&a_coeffs[..], &xs[i])));
    let b_funcs : [_; 8] = array_init(|i| a_funcs[i].clone() + polynomial(&b_minus_a_coeffs[..], &xs[i]));

    let n8_expected = xs.iter().fold(n0, |acc, x| acc.double().double() + x.clone());

    let a8_expected = a_funcs.iter().fold(a0, |acc, ax| acc.double() + ax.clone());
    let b8_expected = b_funcs.iter().fold(b0, |acc, bx| acc.double() + bx.clone());

    let mut constraints = 
        vec![
            n8_expected - n8,
            a8_expected - a8,
            b8_expected - b8
        ];
    constraints.extend(xs.iter().map(nybble));

    E::combine_constraints(alpha0, constraints)
        * v(Column::Index(GateType::EndomulScalar)) 
}

pub fn witness<F: PrimeField + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    x: F,
    endo_scalar: F,
    num_bits: usize) -> F {
    let nybbles_per_row = 8;
    let bits_per_row = 2 * nybbles_per_row;
    assert_eq!(num_bits % bits_per_row, 0);

    let rows = num_bits / bits_per_row;

    let bits_lsb: Vec<_> = BitIteratorLE::new(x.into_repr()).take(num_bits).collect();
    let bits_msb: Vec<_> = bits_lsb.iter().rev().collect();

    let mut a = F::from(2u64);
    let mut b = F::from(2u64);
    let mut n = F::zero();

    let one = F::one();
    let neg_one = -one;

    let a_func = |x: F| -> F {
        if x == F::from(0u64) {
            F::zero()
        } else if x == F::from(1u64) {
            F::zero()
        } else if x == F::from(2u64) {
            -F::one()
        } else if x == F::from(3u64) {
            F::one()
        } else {
            panic!("a_func")
        }
    };

    for i in 0..rows {
        let row = row0 + i;
        w[0][row] = n;
        w[2][row] = a;
        w[3][row] = b;

        for j in 0..nybbles_per_row {
            let bit = bits_per_row * i + 2 * j;

            let b0 = *bits_msb[bit + 1];
            let b1 = *bits_msb[bit];

            let nybble = F::from(b0 as u64) + F::from(b1 as u64).double();
            w[6 + j][row] = nybble;

            a.double_in_place();
            b.double_in_place();

            let s = if b0 { &one } else { &neg_one };

            let a_prev = a;
            if !b1 {
                b += s;
            } else {
                a += s;
            }
            assert_eq!(a, a_prev + a_func(nybble));

            n.double_in_place().double_in_place();
            n += nybble;
        }

        w[1][row] = n;
        w[4][row] = a;
        w[5][row] = b;
    }

    assert_eq!(x, n);

    a * endo_scalar + b
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::{Field, PrimeField, One, Zero, BigInteger};
    use mina_curves::pasta::{fp::{Fp as F}};

    // 2/3*x^3 - 5/2*x^2 + 11/6*x
    fn a_poly(x: F) -> F {
        let x2 = x.square();
        let x3 = x * x2;
        (F::from(2u64) / F::from(3u64)) * x3
            - (F::from(5u64) / F::from(2u64)) * x2
            + (F::from(11u64) / F::from(6u64)) * x
    }

    // -x^2 + 3x - 1
    fn b_minus_a_poly(x: F) -> F {
        let x2 = x.square();
        -F::one() * x2 + F::from(3u64) * x - F::one()
    }

    // Test equivalence of the "a function" in its lookup table,
    // logical, and polynomial forms.
    #[test]
    fn a_func() {
        let f1 = |x: F| -> F {
            if x == F::from(0u64) {
                F::zero()
            } else if x == F::from(1u64) {
                F::zero()
            } else if x == F::from(2u64) {
                -F::one()
            } else if x == F::from(3u64) {
                F::one()
            } else {
                panic!("a_func")
            }
        };

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
            let y3 = a_poly(x);
            assert_eq!(y1, y2);
            assert_eq!(y2, y3);
        }
    }

    // Test equivalence of the "b function" in its lookup table,
    // logical, and polynomial forms.
    #[test]
    fn b_func() {
        let f1 = |x: F| -> F {
            if x == F::from(0u64) {
                -F::one()
            } else if x == F::from(1u64) {
                F::one()
            } else if x == F::from(2u64) {
                F::zero()
            } else if x == F::from(3u64) {
                F::zero()
            } else {
                panic!("a_func")
            }
        };

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
            let y3 = a_poly(x) + b_minus_a_poly(x);
            assert_eq!(y1, y2);
            assert_eq!(y2, y3);
        }
    }
}
