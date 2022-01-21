//! This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.
//!
//! Acc := [2]T
//! for i = n-1 ... 0:
//!   Q := (r_i == 1) ? T : -T
//!   Acc := Acc + (Q + Acc)
//!
//! See https://github.com/zcash/zcash/issues/3924 and 3.1 of https://arxiv.org/pdf/math/0208038.pdf for details.

use crate::circuits::expr::{Cache, Column, Variable, E};
use crate::circuits::gate::{CurrOrNext, GateType};
use crate::circuits::wires::COLUMNS;
use ark_ff::{FftField, One};

type CurveVar = (Variable, Variable);

fn set<F>(w: &mut [Vec<F>; COLUMNS], row0: usize, var: Variable, x: F) {
    match var.col {
        Column::Witness(i) => w[i][row0 + var.row.shift()] = x,
        _ => panic!("Can only set witness columns"),
    }
}

#[allow(clippy::too_many_arguments)]
fn single_bit_witness<F: FftField>(
    w: &mut [Vec<F>; COLUMNS],
    row: usize,
    b: Variable,
    base: CurveVar,
    s1: Variable,
    input: CurveVar,
    output: CurveVar,
    b_value: F,
    base_value: (F, F),
    input_value: (F, F),
) -> (F, F) {
    let mut set = |var, x| set(w, row, var, x);

    set(b, b_value);
    set(input.0, input_value.0);
    set(input.1, input_value.1);

    set(base.0, base_value.0);
    set(base.1, base_value.1);

    let s1_value = (input_value.1 - (base_value.1 * (b_value.double() - F::one())))
        / (input_value.0 - base_value.0);

    set(s1, s1_value);

    let s1_squared = s1_value.square();

    let s2 =
        input_value.1.double() / (input_value.0.double() + base_value.0 - s1_squared) - s1_value;
    let out_x = base_value.0 + s2.square() - s1_squared;
    let out_y = (input_value.0 - out_x) * s2 - input_value.1;
    set(output.0, out_x);
    set(output.1, out_y);
    (out_x, out_y)
}

fn single_bit<F: FftField>(
    cache: &mut Cache,
    b: Variable,
    base: CurveVar,
    s1: Variable,
    input: CurveVar,
    output: CurveVar,
) -> Vec<E<F>> {
    let v = E::Cell;
    let double = |x: E<_>| x.clone() + x;

    let b_sign = double(v(b)) - E::one();

    let s1_squared = cache.cache(v(s1) * v(s1));

    // s1 = (input.y - (2b - 1) * base.y) / (input.x - base.x)
    // s2 = 2*input.y / (2*input.x + base.x – s1^2) - s1
    // output.x = base.x + s2^2 - s1^2
    // output.y = (input.x – output.x) * s2 - input.y

    let rx = s1_squared.clone() - v(input.0) - v(base.0);
    let t = cache.cache(v(input.0) - rx);
    let u = cache.cache(double(v(input.1)) - t.clone() * v(s1));
    // s2 = u / t

    // output.x = base.x + s2^2 - s1^2
    // <=>
    // output.x = base.x + u^2 / t^2 - s1^2
    // output.x - base.x + s1^2 =  u^2 / t^2
    // t^2 (output.x - base.x + s1^2) =  u^2
    //
    // output.y = (input.x – output.x) * s2 - input.y
    // <=>
    // output.y = (input.x – output.x) * (u/t) - input.y
    // output.y + input.y = (input.x – output.x) * (u/t)
    // (output.y + input.y) * t = (input.x – output.x) * u

    vec![
        // boolean constrain the bit.
        v(b) * v(b) - v(b),
        // constrain s1:
        //   (input.x - base.x) * s1 = input.y – (2b-1)*base.y
        (v(input.0) - v(base.0)) * v(s1) - (v(input.1) - b_sign * v(base.1)),
        // constrain output.x
        (u.clone() * u.clone()) - (t.clone() * t.clone()) * (v(output.0) - v(base.0) + s1_squared),
        // constrain output.y
        (v(output.1) + v(input.1)) * t - (v(input.0) - v(output.0)) * u,
    ]
}

struct Layout {
    accs: [(Variable, Variable); 6],
    bits: [Variable; 5],
    ss: [Variable; 5],
    base: (Variable, Variable),
    n_prev: Variable,
    n_next: Variable,
}

// We lay things out like
// 0   1   2   3   4   5   6   7   8   9   10  11  12  13  14
// xT  yT  x0  y0  n   n'      x1  y1  x2  y2  x3  y3  x4  y4
// x5  y5  b0  b1  b2  b3  b4  s0  s1  s2  s3  s4
const fn v(row: CurrOrNext, col: usize) -> Variable {
    Variable {
        row,
        col: Column::Witness(col),
    }
}

use CurrOrNext::*;
const LAYOUT: Layout = Layout {
    accs: [
        (v(Curr, 2), v(Curr, 3)),
        (v(Curr, 7), v(Curr, 8)),
        (v(Curr, 9), v(Curr, 10)),
        (v(Curr, 11), v(Curr, 12)),
        (v(Curr, 13), v(Curr, 14)),
        (v(Next, 0), v(Next, 1)),
    ],
    bits: [v(Next, 2), v(Next, 3), v(Next, 4), v(Next, 5), v(Next, 6)],

    ss: [v(Next, 7), v(Next, 8), v(Next, 9), v(Next, 10), v(Next, 11)],

    base: (v(Curr, 0), v(Curr, 1)),
    n_prev: v(Curr, 4),
    n_next: v(Curr, 5),
};

pub struct VarbaseMulResult<F> {
    pub acc: (F, F),
    pub n: F,
}

pub fn witness<F: FftField + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    base: (F, F),
    bits: &[bool],
    acc0: (F, F),
) -> VarbaseMulResult<F> {
    let l = LAYOUT;
    let bits: Vec<_> = bits.iter().map(|b| F::from(*b as u64)).collect();
    let bits_per_chunk = 5;
    assert_eq!(bits_per_chunk * (bits.len() / bits_per_chunk), bits.len());

    let mut acc = acc0;
    let mut n_acc = F::zero();
    for (chunk, bs) in bits.chunks(bits_per_chunk).enumerate() {
        let row = row0 + 2 * chunk;

        set(w, row, l.n_prev, n_acc);
        for (i, bs) in bs.iter().enumerate().take(bits_per_chunk) {
            n_acc.double_in_place();
            n_acc += bs;
            acc = single_bit_witness(
                w,
                row,
                l.bits[i],
                l.base,
                l.ss[i],
                l.accs[i],
                l.accs[i + 1],
                *bs,
                base,
                acc,
            );
        }
        set(w, row, l.n_next, n_acc);
    }
    VarbaseMulResult { acc, n: n_acc }
}

pub fn constraint<F: FftField>(alphas: impl Iterator<Item = usize>) -> E<F> {
    let Layout {
        base,
        accs,
        bits,
        ss,
        n_prev,
        n_next,
    } = LAYOUT;

    let mut c = Cache::default();

    let mut constraint = |i| single_bit(&mut c, bits[i], base, ss[i], accs[i], accs[i + 1]);

    // n'
    // = 2^5 * n + 2^4 b0 + 2^3 b1 + 2^2 b2 + 2^1 b3 + b4
    // = b4 + 2 (b3 + 2 (b2 + 2 (b1 + 2(b0 + 2 n))))

    let n_prev = E::Cell(n_prev);
    let n_next = E::Cell(n_next);
    let mut res = vec![
        n_next
            - bits
                .iter()
                .fold(n_prev, |acc, b| E::Cell(*b) + acc.double()),
    ];

    for i in 0..5 {
        res.append(&mut constraint(i));
    }
    E::cell(Column::Index(GateType::VarBaseMul), CurrOrNext::Curr)
        * E::combine_constraints(alphas, res)
}
