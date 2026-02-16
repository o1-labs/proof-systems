//! This module implements short Weierstrass curve variable base scalar multiplication custom Plonk polynomials.
//!
//! ```ignore
//! Acc := [2]T
//! for i = n-1 ... 0:
//!   Q := (r_i == 1) ? T : -T
//!   Acc := Acc + (Q + Acc)
//! ```
//!
//! See <https://github.com/zcash/zcash/issues/3924>
//! and 3.1 of <https://arxiv.org/pdf/math/0208038.pdf> for details.

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    berkeley_columns::{BerkeleyChallengeTerm, Column},
    expr::{constraints::ExprOps, Cache, Variable as VariableGen},
    gate::{CircuitGate, CurrOrNext, GateType},
    wires::{GateWires, COLUMNS},
};
use ark_ff::{FftField, PrimeField};
use core::marker::PhantomData;
use CurrOrNext::{Curr, Next};

type Variable = VariableGen<Column>;

//~ We implement custom Plonk constraints for short Weierstrass curve variable base scalar multiplication.
//~
//~ Given a finite field $\mathbb{F}_q$ of order $q$, if the order is not a multiple of 2 nor 3, then an
//~ elliptic curve over $\mathbb{F}_q$ in short Weierstrass form is represented by the set of points $(x,y)$
//~ that satisfy the following equation with $a,b\in\mathbb{F}_q$ and $4a^3+27b^2\neq_{\mathbb{F}_q} 0$:
//~ $$E(\mathbb{F}_q): y^2 = x^3 + a x + b$$
//~ If $P=(x_p, y_p)$ and $Q=(x_q, y_q)$ are two points in the curve $E(\mathbb{F}_q)$, the algorithm we
//~ represent here computes the operation $2P+Q$ (point doubling and point addition) as $(P+Q)+Q$.
//~
//~ ```admonish info
//~ Point $Q=(x_q, y_q)$ has nothing to do with the order $q$ of the field $\mathbb{F}_q$.
//~ ```
//~
//~ The original algorithm that is being used can be found in the Section 3.1 of <https://arxiv.org/pdf/math/0208038.pdf>,
//~ which can perform the above operation using 1 multiplication, 2 squarings and 2 divisions (one more squaring)
//~ if $P=Q$), thanks to the fact that computing the $Y$-coordinate of the intermediate addition is not required.
//~ This is more efficient to the standard algorithm that requires 1 more multiplication, 3 squarings in total and 2 divisions.
//~
//~ Moreover, this algorithm can be applied not only to the operation $2P+Q$, but any other scalar multiplication $kP$.
//~ This can be done by expressing the scalar $k$ in biwise form and performing a double-and-add approach.
//~ Nonetheless, this requires conditionals to differentiate $2P$ from $2P+Q$. For that reason, we will implement
//~ the following pseudocode from <https://github.com/zcash/zcash/issues/3924> (where instead, they give a variant
//~ of the above efficient algorithm for Montgomery curves $b\cdot y^2 = x^3 + a \cdot x^2 + x$).
//~
//~ ```ignore
//~ Acc := [2]T
//~ for i = n-1 ... 0:
//~    Q := (k_{i + 1} == 1) ? T : -T
//~    Acc := Acc + (Q + Acc)
//~ return (k_0 == 0) ? Acc - P : Acc
//~ ```
//~
//~ The layout of the witness requires 2 rows.
//~ The i-th row will be a `VBSM` gate whereas the next row will be a `ZERO` gate.
//~
//~ |  Row  |  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 | Type |
//~ |-------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|------|
//~ |     i | xT | yT | x0 | y0 |  n | n' |    | x1 | y1 | x2 | y2 | x3 | y3 | x4 | y4 | VBSM |
//~ |   i+1 | x5 | y5 | b0 | b1 | b2 | b3 | b4 | s0 | s1 | s2 | s3 | s4 |    |    |    | ZERO |
//~
//~ The gate constraints take care of 5 bits of the scalar multiplication.
//~ Each single bit consists of 4 constraints.
//~ There is one additional constraint imposed on the final number.
//~ Thus, the `VarBaseMul` gate argument requires 21 constraints.
//~
//~ For every bit, there will be one constraint meant to differentiate between addition and subtraction
//~ for the operation $(P±T)+P$:
//~
//~ `S = (P + (b ? T : −T)) + P`
//~
//~ We follow these criteria:
//~
//~ * If the bit is positive, the sign should be a subtraction
//~ * If the bit is negative, the sign should be an addition
//~
//~ Then, paraphrasing the above, we will represent this behavior as:
//~
//~ `S = (P - (2 * b - 1) * T ) + P`
//~
//~ Let us call `Input` the point with coordinates `(xI, yI)` and
//~ `Target` is the point being added with coordinates `(xT, yT)`.
//~ Then `Output` will be the point with coordinates `(xO, yO)` resulting from `O = ( I ± T ) + I`
//~
//~ ```admonish info
//~ Do not confuse our `Output` point `(xO, yO)` with the point at infinity that is normally represented as $\mathcal{O}$.
//~ ```
//~
//~ In each step of the algorithm, we consider the following elliptic curves affine arithmetic equations:
//~
//~ * $s_1 := \frac{y_i - (2\cdot b - 1) \cdot y_t}{x_i - x_t}$
//~ * $s_2 := \frac{2 \cdot y_i}{2 * x_i + x_t - s_1^2} - s_1$
//~ * $x_o := x_t + s_2^2 - s_1^2$
//~ * $y_o := s_2 \cdot (x_i - x_o) - y_i$
//~
//~ For readability, we define the following 3 variables
//~ in such a way that $s_2$ can be expressed as `u / t`:
//~
//~ * `rx` $:= s_1^2 - x_i - x_t$
//~ * `t` $:= x_i - $ `rx` $ \iff 2 \cdot x_i - s_1^2 + x_t$
//~ * `u` $:= 2 \cdot y_i - $ `t` $\cdot s_1 \iff 2 \cdot y_i - s_1 \cdot (2\cdot x_i - s^2_1 + x_t)$
//~
//~ Next, for each bit in the algorithm, we create the following 4 constraints that derive from the above:
//~
//~ * Booleanity check on the bit $b$:
//~ `0 = b * b - b`
//~ * Constrain $s_1$:
//~ `(xI - xT) * s1 = yI – (2b - 1) * yT`
//~ * Constrain `Output` $X$-coordinate $x_o$ and $s_2$:
//~ `0 = u^2 - t^2 * (xO - xT + s1^2)`
//~ * Constrain `Output` $Y$-coordinate $y_o$ and $s_2$:
//~ `0 = (yO + yI) * t - (xI - xO) * u`
//~
//~ When applied to the 5 bits, the value of the `Target` point `(xT, yT)` is maintained,
//~ whereas the values for the `Input` and `Output` points form the chain:
//~
//~ `[(x0, y0) -> (x1, y1) -> (x2, y2) -> (x3, y3) -> (x4, y4) -> (x5, y5)]`
//~
//~ Similarly, 5 different `s0..s4` are required, just like the 5 bits `b0..b4`.
//~
//~ Finally, the additional constraint makes sure that the scalar is being correctly expressed
//~ into its binary form (using the double-and-add decomposition) as:
//~ $$ n' = 2^5 \cdot n + 2^4 \cdot b_0 + 2^3 \cdot b_1 + 2^2 \cdot b_2 + 2^1 \cdot b_3 + b_4$$
//~ This equation is translated as the constraint:
//~
//~ * Binary decomposition:
//~ `0 = n' - (b4 + 2 * (b3 + 2 * (b2 + 2 * (b1 + 2 * (b0 + 2*n)))))`
//~

impl<F: PrimeField> CircuitGate<F> {
    pub fn create_vbmul(wires: &[GateWires; 2]) -> Vec<Self> {
        vec![
            CircuitGate::new(GateType::VarBaseMul, wires[0], vec![]),
            CircuitGate::new(GateType::Zero, wires[1], vec![]),
        ]
    }

    /// Verify the `GateType::VarBaseMul`(TODO)
    ///
    /// # Errors
    ///
    /// TODO
    pub fn verify_vbmul(&self, _row: usize, _witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        // TODO: implement
        Ok(())
    }

    pub fn vbmul(&self) -> F {
        if self.typ == GateType::VarBaseMul {
            F::one()
        } else {
            F::zero()
        }
    }
}

#[derive(Copy, Clone)]
struct Point<T> {
    x: T,
    y: T,
}

impl<T> Point<T> {
    pub fn create(x: T, y: T) -> Self {
        Point { x, y }
    }
}

impl Point<Variable> {
    pub fn new_from_env<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(
        &self,
        env: &ArgumentEnv<F, T>,
    ) -> Point<T> {
        Point::create(self.x.new_from_env(env), self.y.new_from_env(env))
    }
}

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
    base: &Point<Variable>,
    s1: Variable,
    input: &Point<Variable>,
    output: &Point<Variable>,
    b_value: F,
    base_value: (F, F),
    input_value: (F, F),
) -> (F, F) {
    let mut set = |var, x| set(w, row, var, x);

    set(b, b_value);
    set(input.x, input_value.0);
    set(input.y, input_value.1);

    set(base.x, base_value.0);
    set(base.y, base_value.1);

    let s1_value = (input_value.1 - (base_value.1 * (b_value.double() - F::one())))
        / (input_value.0 - base_value.0);

    set(s1, s1_value);

    let s1_squared = s1_value.square();

    let s2 =
        input_value.1.double() / (input_value.0.double() + base_value.0 - s1_squared) - s1_value;
    let out_x = base_value.0 + s2.square() - s1_squared;
    let out_y = (input_value.0 - out_x) * s2 - input_value.1;
    set(output.x, out_x);
    set(output.y, out_y);
    (out_x, out_y)
}

fn single_bit<F: FftField, T: ExprOps<F, BerkeleyChallengeTerm>>(
    cache: &mut Cache,
    b: &T,
    base: Point<T>,
    s1: &T,
    input: &Point<T>,
    output: &Point<T>,
) -> Vec<T> {
    let b_sign = b.double() - T::one();

    let s1_squared = cache.cache(s1.clone() * s1.clone());

    // s1 = (input.y - (2b - 1) * base.y) / (input.x - base.x)
    // s2 = 2*input.y / (2*input.x + base.x – s1^2) - s1
    // output.x = base.x + s2^2 - s1^2
    // output.y = (input.x – output.x) * s2 - input.y

    let rx = s1_squared.clone() - input.x.clone() - base.x.clone();
    let t = cache.cache(input.x.clone() - rx);
    let u = cache.cache(input.y.double() - t.clone() * s1.clone());
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
        b.boolean(),
        // constrain s1:
        //   (input.x - base.x) * s1 = input.y – (2b-1)*base.y
        (input.x.clone() - base.x.clone()) * s1.clone() - (input.y.clone() - b_sign * base.y),
        // constrain output.x
        (u.clone() * u.clone())
            - (t.clone() * t.clone()) * (output.x.clone() - base.x + s1_squared),
        // constrain output.y
        (output.y.clone() + input.y.clone()) * t - (input.x.clone() - output.x.clone()) * u,
    ]
}

pub struct Layout<T> {
    accs: [Point<T>; 6],
    bits: [T; 5],
    ss: [T; 5],
    base: Point<T>,
    n_prev: T,
    n_next: T,
}

trait FromWitness<F, T>
where
    F: PrimeField,
{
    fn new_from_env(&self, env: &ArgumentEnv<F, T>) -> T;
}

impl<F, T> FromWitness<F, T> for Variable
where
    F: PrimeField,
    T: ExprOps<F, BerkeleyChallengeTerm>,
{
    fn new_from_env(&self, env: &ArgumentEnv<F, T>) -> T {
        let column_to_index = |_| match self.col {
            Column::Witness(i) => i,
            _ => panic!("Can't get index from witness columns"),
        };

        match self.row {
            Curr => env.witness_curr(column_to_index(self.col)),
            Next => env.witness_next(column_to_index(self.col)),
        }
    }
}

impl Layout<Variable> {
    fn create() -> Self {
        Layout {
            accs: [
                Point::create(v(Curr, 2), v(Curr, 3)),   // (x0, y0)
                Point::create(v(Curr, 7), v(Curr, 8)),   // (x1, y1)
                Point::create(v(Curr, 9), v(Curr, 10)),  // (x2, y2)
                Point::create(v(Curr, 11), v(Curr, 12)), // (x3, y3)
                Point::create(v(Curr, 13), v(Curr, 14)), // (x4, y4)
                Point::create(v(Next, 0), v(Next, 1)),   // (x5, y5)
            ],
            // bits = [b0, b1, b2, b3, b4]
            bits: [v(Next, 2), v(Next, 3), v(Next, 4), v(Next, 5), v(Next, 6)],

            // ss = [ s0, s1, s2, s3, s4]
            ss: [v(Next, 7), v(Next, 8), v(Next, 9), v(Next, 10), v(Next, 11)],

            base: Point::create(v(Curr, 0), v(Curr, 1)), // (xT, yT)
            n_prev: v(Curr, 4),                          // n
            n_next: v(Curr, 5),                          // n'
        }
    }

    fn new_from_env<F: PrimeField, T: ExprOps<F, BerkeleyChallengeTerm>>(
        &self,
        env: &ArgumentEnv<F, T>,
    ) -> Layout<T> {
        Layout {
            accs: self.accs.map(|point| point.new_from_env(env)),
            bits: self.bits.map(|var| var.new_from_env(env)),
            ss: self.ss.map(|s| s.new_from_env(env)),
            base: self.base.new_from_env(env),
            n_prev: self.n_prev.new_from_env(env),
            n_next: self.n_next.new_from_env(env),
        }
    }
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

pub struct VarbaseMulResult<F> {
    pub acc: (F, F),
    pub n: F,
}

/// Apply the `witness` value.
///
/// # Panics
///
/// Will panic if `bits chunk` length validation fails.
pub fn witness<F: FftField + core::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    base: (F, F),
    bits: &[bool],
    acc0: (F, F),
) -> VarbaseMulResult<F> {
    let layout = Layout::create();
    let bits: Vec<_> = bits.iter().map(|b| F::from(u64::from(*b))).collect();
    let bits_per_chunk = 5;
    assert_eq!(bits_per_chunk * (bits.len() / bits_per_chunk), bits.len());

    let mut acc = acc0;
    let mut n_acc = F::zero();
    for (chunk, bs) in bits.chunks(bits_per_chunk).enumerate() {
        let row = row0 + 2 * chunk;

        set(w, row, layout.n_prev, n_acc);
        for (i, bs) in bs.iter().enumerate().take(bits_per_chunk) {
            n_acc.double_in_place();
            n_acc += bs;
            acc = single_bit_witness(
                w,
                row,
                layout.bits[i],
                &layout.base,
                layout.ss[i],
                &layout.accs[i],
                &layout.accs[i + 1],
                *bs,
                base,
                acc,
            );
        }
        set(w, row, layout.n_next, n_acc);
    }
    VarbaseMulResult { acc, n: n_acc }
}

/// Implementation of the `VarbaseMul` gate
#[derive(Default)]
pub struct VarbaseMul<F>(PhantomData<F>);

impl<F> Argument<F> for VarbaseMul<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::VarBaseMul);
    const CONSTRAINTS: u32 = 21;

    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        cache: &mut Cache,
    ) -> Vec<T> {
        let Layout {
            base,
            accs,
            bits,
            ss,
            n_prev,
            n_next,
        } = Layout::create().new_from_env::<F, T>(env);

        // n'
        // = 2^5 * n + 2^4 b0 + 2^3 b1 + 2^2 b2 + 2^1 b3 + b4
        // = b4 + 2 (b3 + 2 (b2 + 2 (b1 + 2(b0 + 2 n))))

        let mut res = vec![n_next - bits.iter().fold(n_prev, |acc, b| b.clone() + acc.double())];

        for i in 0..5 {
            res.append(&mut single_bit(
                cache,
                &bits[i],
                base.clone(),
                &ss[i],
                &accs[i],
                &accs[i + 1],
            ));
        }

        res
    }
}
