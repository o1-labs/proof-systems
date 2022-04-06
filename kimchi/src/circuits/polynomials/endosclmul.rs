//! This module implements short Weierstrass curve
//! endomorphism optimised variable base
//! scalar multiplication custom Plonk polynomials.

use std::marker::PhantomData;

use ark_ff::{FftField, Field, One};

use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::gate::CircuitGate;
use crate::circuits::wires::GateWires;
use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr,
    expr::{constraints::boolean, prologue::*, Cache, ConstantExpr},
    gate::GateType,
    wires::COLUMNS,
};
use crate::proof::ProofEvaluations;

//~ We implement custom gate constraints for short Weierstrass curve
//~ endomorphism optimised variable base scalar multiplication.
//~
//~ Given a finite field $\mathbb{F}_q$ of order $q$, if the order is not a multiple of 2 nor 3, then an
//~ elliptic curve over $\mathbb{F}_q$ in short Weierstrass form is represented by the set of points $(x,y)$
//~ that satisfy the following equation with $a,b\in\mathbb{F}_q$ and $4a^3+27b^2\neq_{\mathbb{F}_q} 0$:
//~ $$E(\mathbb{F}_q): y^2 = x^3 + a x + b$$
//~ If $P=(x_p, y_p)$ and $T=(x_t, y_t)$ are two points in the curve $E(\mathbb{F}_q)$, the goal of this
//~ operation is to perform the operation $2P±T$ efficiently as $(P±T)+P$.
//~
//~ `S = (P + (b ? T : −T)) + P`
//~
//~ The same algorithm can be used to perform other scalar multiplications, meaning it is
//~ not restricted to the case $2\cdot P$, but it can be used for any arbitrary $k\cdot P$. This is done
//~ by decomposing the scalar $k$ into its binary representation.
//~ Moreover, for every step, there will be a one-bit constraint meant to differentiate between addition and subtraction
//~ for the operation $(P±T)+P$:
//~
//~ In particular, the constraints of this gate take care of 4 bits of the scalar within a single EVBSM row.
//~ When the scalar is longer (which will usually be the case), multiple EVBSM rows will be concatenated.
//~
//~ |  Row  |  0 |  1 |  2 |  3 |  4 |  5 |  6 |   7 |   8 |   9 |  10 |  11 |  12 |  13 |  14 |  Type |
//~ |-------|----|----|----|----|----|----|----|-----|-----|-----|-----|-----|-----|-----|-----|-------|
//~ |     i | xT | yT |  Ø |  Ø | xP | yP | n  |  xR |  yR |  s1 | s3  | b1  |  b2 |  b3 |  b4 | EVBSM |
//~ |   i+1 |  = |  = |    |    | xS | yS | n' | xR' | yR' | s1' | s3' | b1' | b2' | b3' | b4' | EVBSM |
//~
//~ The layout of this gate (and the next row) allows for this chained behavior where the output point
//~ of the current row $S$ gets accumulated as one of the inputs of the following row, becoming $P$ in
//~ the next constraints. Similarly, the scalar is decomposed into binary form and $n$ ($n'$ respectively)
//~ will store the current accumulated value and the next one for the check.
//~
//~ For readability, we define the following variables for the constraints:
//~
//~   * `endo` $:=$ `EndoCoefficient`
//~   * `xq1` $:= (1 + ($`endo`$ - 1)\cdot b_1) \cdot x_t$
//~   * `xq2` $:= (1 + ($`endo`$ - 1)\cdot b_3) \cdot x_t$
//~   * `yq1` $:= (2\cdot b_2 - 1) \cdot y_t$
//~   * `yq2` $:= (2\cdot b_4 - 1) \cdot y_t$
//~
//~ These are the 11 constraints that correspond to each EVBSM gate,
//~ which take care of 4 bits of the scalar within a single EVBSM row:
//~
//~ * First block:
//~   * `(xq1 - xp) * s1 = yq1 - yp`
//~   * `(2 * xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2 * yp`
//~   * `(yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)`
//~ * Second block:
//~   * `(xq2 - xr) * s3 = yq2 - yr`
//~   * `(2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2 * yr`
//~   * `(ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)`
//~ * Booleanity checks:
//~   * Bit flag $b_1$: `0 = b1 * (b1 - 1)`
//~   * Bit flag $b_2$: `0 = b2 * (b2 - 1)`
//~   * Bit flag $b_3$: `0 = b3 * (b3 - 1)`
//~   * Bit flag $b_4$: `0 = b4 * (b4 - 1)`
//~ * Binary decomposition:
//~   * Accumulated scalar: `n_next = 16 * n + 8 * b1 + 4 * b2 + 2 * b3 + b4`
//~
//~ The constraints above are derived from the following EC Affine arithmetic equations:
//~
//~ * (1) => $(x_{q_1} - x_p) \cdot s_1 = y_{q_1} - y_p$
//~ * (2&3) => $(x_p – x_r) \cdot s_2 = y_r + y_p$
//~ * (2) => $(2 \cdot x_p + x_{q_1} – s_1^2) \cdot (s_1 + s_2) = 2 \cdot y_p$
//~     * <=> $(2 \cdot x_p – s_1^2 + x_{q_1}) \cdot ((x_p – x_r) \cdot s_1 + y_r + y_p) = (x_p – x_r) \cdot 2 \cdot y_p$
//~ * (3) => $s_1^2 - s_2^2 = x_{q_1} - x_r$
//~     * <=> $(y_r + y_p)^2 = (x_p – x_r)^2 \cdot (s_1^2 – x_{q_1} + x_r)$
//~ *
//~ * (4) => $(x_{q_2} - x_r) \cdot s_3 = y_{q_2} - y_r$
//~ * (5&6) => $(x_r – x_s) \cdot s_4 = y_s + y_r$
//~ * (5) => $(2 \cdot x_r + x_{q_2} – s_3^2) \cdot (s_3 + s_4) = 2 \cdot y_r$
//~     * <=> $(2 \cdot x_r – s_3^2 + x_{q_2}) \cdot ((x_r – x_s) \cdot s_3 + y_s + y_r) = (x_r – x_s) \cdot 2 \cdot y_r$
//~ * (6) => $s_3^2 – s_4^2 = x_{q_2} - x_s$
//~     * <=> $(y_s + y_r)^2 = (x_r – x_s)^2 \cdot (s_3^2 – x_{q_2} + x_s)$
//~
//~ Defining $s_2$ and $s_4$ as
//~
//~ * $s_2 := \frac{2 \cdot y_P}{2 * x_P + x_T - s_1^2} - s_1$
//~ * $s_4 := \frac{2 \cdot y_R}{2 * x_R + x_T - s_3^2} - s_3$
//~
//~ Gives the following equations when substituting the values of $s_2$ and $s_4$:
//~
//~ 1. `(xq1 - xp) * s1 = (2 * b1 - 1) * yt - yp`
//~ 2. `(2 * xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2 * yp`
//~ 3. `(yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)`
//~ -
//~ 4. `(xq2 - xr) * s3 = (2 * b2 - 1) * yt - yr`
//~ 5. `(2 * xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2 * yr`
//~ 6. `(ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)`
//~

/// Implementation of group endomorphism optimised
/// variable base scalar multiplication custom Plonk constraints.
impl<F: FftField> CircuitGate<F> {
    pub fn create_endomul(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::EndoMul,
            wires,
            coeffs: vec![],
        }
    }

    pub fn verify_endomul(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(self.typ, GateType::EndoMul, "incorrect gate type");

        let this: [F; COLUMNS] = array_init::array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init::array_init(|i| witness[i][row + 1]);

        let pt = F::from(123456u64);

        let constants = expr::Constants {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: None,
            mds: vec![],
            endo_coefficient: cs.endo,
        };

        let evals: [ProofEvaluations<F>; 2] = [
            ProofEvaluations::dummy_with_witness_evaluations(this),
            ProofEvaluations::dummy_with_witness_evaluations(next),
        ];

        let constraints = EndosclMul::constraints();
        for (i, c) in constraints.iter().enumerate() {
            match c.evaluate_(cs.domain.d1, pt, &evals, &constants) {
                Ok(x) => {
                    if x != F::zero() {
                        return Err(format!("Bad endo equation {}", i));
                    }
                }
                Err(e) => return Err(format!("evaluation failed: {}", e)),
            }
        }

        Ok(())
    }

    pub fn endomul(&self) -> F {
        if self.typ == GateType::EndoMul {
            F::one()
        } else {
            F::zero()
        }
    }
}

/// Implementation of the EndosclMul gate.
pub struct EndosclMul<F>(PhantomData<F>);

impl<F> Argument<F> for EndosclMul<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::EndoMul);
    const CONSTRAINTS: u32 = 11;

    fn constraints() -> Vec<E<F>> {
        let b1 = witness_curr(11);
        let b2 = witness_curr(12);
        let b3 = witness_curr(13);
        let b4 = witness_curr(14);

        let xt = witness_curr(0);
        let yt = witness_curr(1);

        let xs = witness_next(4);
        let ys = witness_next(5);

        let xp = witness_curr(4);
        let yp = witness_curr(5);

        let xr = witness_curr(7);
        let yr = witness_curr(8);

        let mut cache = Cache::default();

        let s1 = witness_curr(9);
        let s3 = witness_curr(10);

        let endo_minus_1 = E::Constant(ConstantExpr::EndoCoefficient - ConstantExpr::one());
        let xq1 = cache.cache((E::one() + b1.clone() * endo_minus_1.clone()) * xt.clone());
        let xq2 = cache.cache((E::one() + b3.clone() * endo_minus_1) * xt);

        let yq1 = (b2.clone().double() - E::one()) * yt.clone();
        let yq2 = (b4.clone().double() - E::one()) * yt;

        let s1_squared = cache.cache(s1.clone().square());
        let s3_squared = cache.cache(s3.clone().square());

        // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
        let n = witness_curr(6);
        let n_next = witness_next(6);
        let n_constraint =
            (((n.double() + b1.clone()).double() + b2.clone()).double() + b3.clone()).double()
                + b4.clone()
                - n_next;

        let xp_xr = cache.cache(xp.clone() - xr.clone());
        let xr_xs = cache.cache(xr.clone() - xs.clone());

        let ys_yr = cache.cache(ys + yr.clone());
        let yr_yp = cache.cache(yr.clone() + yp.clone());

        vec![
            // verify booleanity of the scalar bits
            boolean(&b1),
            boolean(&b2),
            boolean(&b3),
            boolean(&b4),
            // (xq1 - xp) * s1 = yq1 - yp
            ((xq1.clone() - xp.clone()) * s1.clone()) - (yq1 - yp.clone()),
            // (2*xp – s1^2 + xq1) * ((xp - xr) * s1 + yr + yp) = (xp - xr) * 2*yp
            (((xp.double() - s1_squared.clone()) + xq1.clone())
                * ((xp_xr.clone() * s1) + yr_yp.clone()))
                - (yp.double() * xp_xr.clone()),
            // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
            yr_yp.square() - (xp_xr.square() * ((s1_squared - xq1) + xr.clone())),
            // (xq2 - xr) * s3 = yq2 - yr
            ((xq2.clone() - xr.clone()) * s3.clone()) - (yq2 - yr.clone()),
            // (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr - xs) * 2*yr
            (((xr.double() - s3_squared.clone()) + xq2.clone())
                * ((xr_xs.clone() * s3) + ys_yr.clone()))
                - (yr.double() * xr_xs.clone()),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
            ys_yr.square() - (xr_xs.square() * ((s3_squared - xq2) + xs)),
            n_constraint,
        ]
    }
}

/// The result of performing an endoscaling: the accumulated curve point
/// and scalar.
pub struct EndoMulResult<F> {
    pub acc: (F, F),
    pub n: F,
}

/// Generates the witness_curr values for a series of endoscaling constraints.
pub fn gen_witness<F: Field + std::fmt::Display>(
    w: &mut [Vec<F>; COLUMNS],
    row0: usize,
    endo: F,
    base: (F, F),
    bits: &[bool],
    acc0: (F, F),
) -> EndoMulResult<F> {
    let bits_per_row = 4;
    let rows = bits.len() / 4;
    assert_eq!(0, bits.len() % 4);

    let bits: Vec<_> = bits.iter().map(|x| F::from(*x as u64)).collect();
    let one = F::one();

    let mut acc = acc0;
    let mut n_acc = F::zero();

    // TODO: Could be more efficient
    for i in 0..rows {
        let b1 = bits[i * bits_per_row];
        let b2 = bits[i * bits_per_row + 1];
        let b3 = bits[i * bits_per_row + 2];
        let b4 = bits[i * bits_per_row + 3];

        let (xt, yt) = base;
        let (xp, yp) = acc;

        let xq1 = (one + (endo - one) * b1) * xt;
        let yq1 = (b2.double() - one) * yt;

        let s1 = (yq1 - yp) / (xq1 - xp);
        let s1_squared = s1.square();
        // (2*xp – s1^2 + xq) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
        // => 2 yp / (2*xp – s1^2 + xq) = s1 + (yr + yp) / (xp – xr)
        // => 2 yp / (2*xp – s1^2 + xq) - s1 = (yr + yp) / (xp – xr)
        //
        // s2 := 2 yp / (2*xp – s1^2 + xq) - s1
        //
        // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)
        // => (s1^2 – xq1 + xr) = (yr + yp)^2 / (xp – xr)^2
        //
        // => xr = s2^2 - s1^2 + xq
        // => yr = s2 * (xp - xr) - yp
        let s2 = yp.double() / (xp.double() + xq1 - s1_squared) - s1;

        // (xr, yr)
        let xr = xq1 + s2.square() - s1_squared;
        let yr = (xp - xr) * s2 - yp;

        let xq2 = (one + (endo - one) * b3) * xt;
        let yq2 = (b4.double() - one) * yt;
        let s3 = (yq2 - yr) / (xq2 - xr);
        let s3_squared = s3.square();
        let s4 = yr.double() / (xr.double() + xq2 - s3_squared) - s3;

        let xs = xq2 + s4.square() - s3_squared;
        let ys = (xr - xs) * s4 - yr;

        let row = i + row0;

        w[0][row] = base.0;
        w[1][row] = base.1;
        w[4][row] = xp;
        w[5][row] = yp;
        w[6][row] = n_acc;
        w[7][row] = xr;
        w[8][row] = yr;
        w[9][row] = s1;
        w[10][row] = s3;
        w[11][row] = b1;
        w[12][row] = b2;
        w[13][row] = b3;
        w[14][row] = b4;

        acc = (xs, ys);

        n_acc.double_in_place();
        n_acc += b1;
        n_acc.double_in_place();
        n_acc += b2;
        n_acc.double_in_place();
        n_acc += b3;
        n_acc.double_in_place();
        n_acc += b4;
    }
    w[4][row0 + rows] = acc.0;
    w[5][row0 + rows] = acc.1;
    w[6][row0 + rows] = n_acc;

    EndoMulResult { acc, n: n_acc }
}
