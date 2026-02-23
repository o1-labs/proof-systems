//! This module implements the **EndoMul** gate for short Weierstrass curve
//! endomorphism-optimized variable base scalar multiplication.
//!
//! # Purpose
//!
//! Compute `[scalar] * base_point` where the scalar is given as bits and the
//! base point is a curve point. This is the core operation for EC-based
//! cryptography in-circuit.
//!
//! # Notation
//!
//! - `T`: The fixed base point for the full scalar multiplication
//! - `P`: The running accumulator point (changes row by row)
//!
//! # Inputs (per row)
//!
//! - `(x_T, y_T)`: Base point T being multiplied (columns 0, 1)
//! - `(x_P, y_P)`: Current accumulator point P (columns 4, 5)
//! - `n`: Current accumulated scalar value (column 6)
//! - `b1, b2, b3, b4`: Four scalar bits for this row (columns 11-14)
//!
//! # Outputs (in next row)
//!
//! - `(x_S, y_S)`: Updated accumulator point after processing 4 bits (cols 4,5)
//! - `n'`: Updated accumulated scalar: `n' = 16*n + 8*b1 + 4*b2 + 2*b3 + b4`
//!
//! # Endomorphism-optimized scalar multiplication
//!
//! For curves of the form y^2 = x^3 + b (like Pallas and Vesta), there exists
//! an efficient endomorphism phi defined by:
//!
//!   phi(x, y) = (endo * x, y)
//!
//! where `endo` (also called xi) is a primitive cube root of unity in the base
//! field. This works because (endo * x)^3 = endo^3 * x^3 = x^3, so the point
//! remains on the curve.
//!
//! This endomorphism corresponds to scalar multiplication by lambda:
//!
//!   phi(T) = [lambda]T
//!
//! where lambda is a primitive cube root of unity in the scalar field.
//!
//! ## How the optimization works
//!
//! The key insight is that we can compute `P + phi(T)` or `P - phi(T)` almost
//! as cheaply as `P + T` or `P - T`, because applying phi only requires
//! multiplying the x-coordinate by `endo`.
//!
//! For a 2-bit window (b1, b2), we can encode 4 different point operations:
//!
//! | b1 | b2 | Point Q added to accumulator P |
//! |----|----|--------------------|
//! |  0 |  0 |  -T                |
//! |  0 |  1 |   T                |
//! |  1 |  0 |  -phi(T)           |
//! |  1 |  1 |   phi(T)           |
//!
//! This is achieved by:
//! - `xq = (1 + (endo - 1) * b1) * x_T` = x_T if b1=0, or endo * x_T if b1=1
//! - `yq = (2 * b2 - 1) * y_T` = -y_T if b2=0, or y_T if b2=1
//!
//! So (xq, yq) represents one of {T, -T, phi(T), -phi(T)} based on (b1, b2).
//!
//! ## Why phi(T)? The GLV optimization
//!
//! When we want to compute `[k]T` for a large scalar `k`, a standard
//! variable-base method uses roughly one double-and-add update per scalar bit
//! (~256 updates for a 256-bit scalar). The GLV method
//! (Gallant-Lambert-Vanstone) cuts this roughly in half.
//!
//! The key insight is that any scalar k can be decomposed as:
//!
//!   k = k1 + k2 * lambda (mod r)
//!
//! where k1, k2 are roughly half the bit-length of k (about 128 bits each).
//! Since `phi(T) = [lambda]T`, we can rewrite:
//!
//!   [k]T = [k1]T + [k2][lambda]T = [k1]T + [k2]phi(T)
//!
//! Now instead of one 256-bit scalar multiplication, we have two 128-bit scalar
//! multiplications: `[k1]T` and `[k2]phi(T)`. But we can do even better by
//! computing both **simultaneously** using a multi-scalar multiplication
//! approach.
//!
//! In each step, we process one bit from k1 and one bit from k2 together. The
//! 2-bit encoding (b1, b2) selects which combination of T and phi(T) to add:
//!
//! - b1 selects between T (b1=0) and phi(T) (b1=1)
//! - b2 selects the sign: negative (b2=0) or positive (b2=1)
//!
//! | b1 | b2 | Point added |
//! |----|----|-------------|
//! |  0 |  0 |  -T         |
//! |  0 |  1 |   T         |
//! |  1 |  0 |  -phi(T)    |
//! |  1 |  1 |   phi(T)    |
//!
//! The negative points come from the y-coordinate formula: `yq = (2*b2 - 1)*y_T`.
//! When b2=0, we get `-y_T`, which negates the point (since `-P = (x, -y)` on
//! elliptic curves). We need both positive and negative points to encode the
//! scalar using a **signed digit representation**. With 2 bits we represent 4
//! distinct values `{-1, +1} x {T, phi(T)}`, which is more expressive than just
//! `{0, 1} x {T, phi(T)}`. This signed representation is part of what makes the
//! GLV method efficient - it allows the scalar decomposition to use both
//! positive and negative contributions.
//!
//! This interleaves the bits of k1 and k2, processing one bit of each per
//! accumulator update. Since k1 and k2 are ~128 bits, we need only ~128 updates
//! instead of ~256, halving the circuit size.
//!
//! The gate processes 4 bits per row (two consecutive accumulator updates),
//! so a 128-bit scalar requires 32 rows of EndoMul gates.
//!
//! ## Protocol fit
//!
//! In Kimchi/Snarky terminology, this gate enforces the **EC_endoscale**
//! point-update constraint (the point side of endomorphism-optimized scaling
//! rounds). In Pickles terms, this corresponds to endomorphism-optimized
//! point updates used with scalar challenges.
//!
//! This gate is used to implement recursive verifier IPA/bulletproof
//! point-folding logic efficiently (GLV endomorphism optimization), including
//! repeated accumulator updates of the form `A <- (A + Q) + A`.
//!
//! Typical protocol usage:
//!
//! - **Wrap proofs**: used as part of normal wrap-circuit verification of step
//!   proofs (part of the wrap recursion flow).
//! - **Step proofs (recursive setting)**: used when the step circuit verifies
//!   previous proofs (e.g. `max_proofs_verified > 0`).
//! - **Non-recursive step circuits**: not inherently required; if no recursive
//!   verification gadget is instantiated, this gate need not be active.
//!
//! ## Usage
//!
//! To compute `[scalar] * base` for a 128-bit scalar:
//!
//! 1. **Set up gates**: Create 32 consecutive EndoMul gates (128 bits / 4 bits
//!    per row), followed by one Zero gate. The Zero gate is required because
//!    each EndoMul gate reads the accumulator from the next row.
//!
//! 2. **Compute initial accumulator**: To avoid point-at-infinity edge cases,
//!    initialize the accumulator as `acc0 = 2 * (T + phi(T))` where T is the
//!    base point and phi is the endomorphism.
//!
//! 3. **Prepare scalar bits**: Convert the scalar to bits in **MSB-first**
//!    order (most significant bit at index 0).
//!
//! 4. **Generate witness**: Call `gen_witness` with the witness array, starting
//!    row, endo coefficient, base point coordinates, MSB-first bits, and
//!    initial accumulator. The function returns the final accumulated point
//!    and the reconstructed scalar value.
//!
//! See `kimchi/src/tests/endomul.rs` for a complete example.
//!
//! ## Invariants
//!
//! The following invariants **must** be respected:
//!
//! 1. **Bit count**: `bits.len()` must be a multiple of 4.
//!
//! 2. **Bit order**: Bits must be in **MSB-first** order (most significant bit
//!    at index 0).
//!
//! 3. **Gate chain**: For `n` bits, you need `n/4` consecutive EndoMul gates,
//!    followed by a Zero gate (or any gate that doesn't constrain the EndoMul
//!    output columns). The Zero gate is needed because EndoMul reads from the
//!    next row.
//!
//! 4. **Initial accumulator**: `acc0` must not be the point at infinity. The
//!    standard initialization is `acc0 = 2 * (T + phi(T))` where T is the base
//!    point. This ensures the accumulator never hits the point at infinity
//!    during computation.
//!
//! 5. **Endo coefficient**: The `endo` parameter must be the correct cube root
//!    of unity for the curve, obtained via `endos::<Curve>()`.
//!
//! 6. **Base point consistency**: The base point `(x_T, y_T)` must be the same
//!    across all rows of a single scalar multiplication.
//!
//! 7. **Scalar value verification**: The EndoMul gate only constrains the
//!    row-to-row relationship `n' = 16*n + 8*b1 + 4*b2 + 2*b3 + b4`. It does
//!    **not** constrain the initial or final value of `n`. The calling circuit
//!    must add external constraints.
//!    To enforce:
//!    - Initial `n = 0` at the first EndoMul row
//!    - Final `n = k` where `k` is the expected scalar value
//!
//! ## References
//!
//! - Halo paper, Section 6.2: <https://eprint.iacr.org/2019/1021>
//! - GLV method: <https://www.iacr.org/archive/crypto2001/21390189.pdf>

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
        constraints::ConstraintSystem,
        expr::{
            self,
            constraints::{boolean, ExprOps},
            Cache,
        },
        gate::{CircuitGate, GateType},
        wires::{GateWires, COLUMNS},
    },
    curve::KimchiCurve,
    proof::{PointEvaluations, ProofEvaluations},
};
use ark_ff::{Field, PrimeField};
use core::marker::PhantomData;

//~ We implement custom gate constraints for short Weierstrass curve
//~ endomorphism optimized variable base scalar multiplication.
//~
//~ Given a finite field $\mathbb{F}_{q}$ of order $q$, if the order is not a
//~ multiple of 2 nor 3, then an
//~ elliptic curve over $\mathbb{F}_{q}$ in short Weierstrass form is
//~ represented by the set of points $(x,y)$ that satisfy the following
//~ equation with $a,b\in\mathbb{F}_{q}$ and $4a^3+27b^2\neq_{\mathbb{F}_q} 0$:
//~ $$E(\mathbb{F}_q): y^2 = x^3 + a x + b$$
//~ If $P=(x_p, y_p)$ and $T=(x_t, y_t)$ are two points in the curve
//~ $E(\mathbb{F}_q)$, the goal of this operation is to compute
//~ $S = (P + Q) + P$ where $Q \in \{T, -T, \phi(T), -\phi(T)\}$ is determined
//~ by bits $(b_1, b_2)$. Here $\phi$ is the curve endomorphism
//~ $\phi(x,y) = (\mathtt{endo} \cdot x, y)$.
//~
//~ The bits encode the point $Q$ as follows:
//~ * $b_1 = 0$: use $T$, i.e., $x_q = x_t$
//~ * $b_1 = 1$: use $\phi(T)$, i.e., $x_q = \mathtt{endo} \cdot x_t$
//~ * $b_2 = 0$: negate, i.e., $y_q = -y_t$
//~ * $b_2 = 1$: keep sign, i.e., $y_q = y_t$
//~
//~ This technique allows processing 2 bits of the scalar per point operation.
//~ Since each row performs two such operations (using bits $b_1, b_2$ and then
//~ $b_3, b_4$), we process 4 bits per row.
//~
//~ In particular, the constraints of this gate take care of 4 bits of the
//~ scalar within a single EVBSM row. When the scalar is longer (which will
//~ usually be the case), multiple EVBSM rows will be concatenated.
//~
//~ | Row | 0  | 1  | 2    | 3 | 4  | 5  | 6  | 7   | 8   | 9   | 10  | 11  | 12  | 13  | 14  | Type  |
//~ |-----|----|----|------|---|----|----|----|-----|-----|-----|-----|-----|-----|-----|-----|-------|
//~ |   i | xT | yT | inv  | Ø | xP | yP | n  | xR  | yR  | s1  | s3  | b1  | b2  | b3  | b4  | EVBSM |
//~ | i+1 | =  | =  | inv' |   | xS | yS | n' | xR' | yR' | s1' | s3' | b1' | b2' | b3' | b4' | EVBSM |
//~
//~ The gate performs two accumulator updates per row, each of the form
//~ `A <- (A + Q) + A = 2A + Q`.
//~
//~ - First, bits `(b1, b2)` select `Q1` in `{T, -T, \phi(T), -\phi(T)}`, and the
//~ stored point `R = (xR, yR)` is the output of the first update: `R = (P + Q1) + P`.
//~ - Second, bits `(b3, b4)` select `Q2` in the same set, and the stored point
//~ `S = (xS, yS)` is the output of the second update: `S = (R + Q2) + R`.
//~
//~ The intermediate sums `P + Q1` and `R + Q2` are not stored as witness
//~ columns. On the next row, `(xS, yS)` becomes the new `(xP, yP)`, and
//~ `(xR', yR')` is the next row's first-update output.
//~
//~ The variables (`xT`, `yT`), (`xP`, `yP`), (`xR`, `yR`), and (`xS`, `yS`)
//~ are the corresponding affine coordinates of points `T`, `P`, `R`, and `S`.
//~
//~ `n` and `n'` are accumulated scalar prefixes in MSB-first order, where `n'`
//~ extends `n` with the next 4-bit chunk encoded by `b1..b4` with `n ≤ n'``.
//~ `s1` and `s3` are intermediary values used to compute the slopes from the
//~ curve addition formula.
//~
//~ The layout of this gate (and the next row) allows for this chained behavior where the output point
//~ of the current row $S$ gets accumulated as one of the inputs of the following row, becoming $P$ in
//~ the next constraints. Similarly, the scalar is decomposed into binary form and $n$ ($n'$ respectively)
//~ will store the current accumulated value and the next one for the check.
//~
//~ For readability, we define the following variables for the constraints:
//~
//~ * `endo` $:=$ `EndoCoefficient`
//~ * `xq1` $:= (1 + ($`endo`$ - 1)\cdot b_1) \cdot x_t$
//~ * `xq2` $:= (1 + ($`endo`$ - 1)\cdot b_3) \cdot x_t$
//~ * `yq1` $:= (2\cdot b_2 - 1) \cdot y_t$
//~ * `yq2` $:= (2\cdot b_4 - 1) \cdot y_t$
//~
//~ Note: each row is performing two additions, so we use two selected points:
//~ `Q1 := (xq1, yq1)` from bits `(b1, b2)` and `Q2 := (xq2, yq2)` from bits
//~ `(b3, b4)`. They are points, and each is selected from
//~ `Q:={T, -T, \phi(T), -\phi(T)}` by its corresponding bit pair. That means:
//~
//~ Selection table for the first selected point `Q1`:
//~
//~ | b1 | b2 | Q1       | (xq1, yq1)               |
//~ |----|----|----------|--------------------------|
//~ | 0  | 0  | -T       | (x_t, -y_t)              |
//~ | 0  | 1  |  T       | (x_t,  y_t)              |
//~ | 1  | 0  | -\phi(T) | (`endo` \cdot x_t, -y_t) |
//~ | 1  | 1  |  \phi(T) | (`endo` \cdot x_t,  y_t) |
//~
//~ Selection table for the second selected point `Q2`:
//~
//~ | b3 | b4 | Q2       | (xq2, yq2)               |
//~ |----|----|----------|--------------------------|
//~ | 0  | 0  | -T       | (x_t, -y_t)              |
//~ | 0  | 1  |  T       | (x_t,  y_t)              |
//~ | 1  | 0  | -\phi(T) | (`endo` \cdot x_t, -y_t) |
//~ | 1  | 1  |  \phi(T) | (`endo` \cdot x_t,  y_t) |
//~
//~ These are the 12 constraints that correspond to each EVBSM gate,
//~ which take care of 4 bits of the scalar within a single EVBSM row:
//~
//~ * First block:
//~   * `(xq1 - xp) * s1 = yq1 - yp`
//~   * `(2*xp - s1^2 + xq1) * ((xp - xr)*s1 + yr + yp) = (xp - xr) * 2*yp`
//~   * `(yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)`
//~ * Second block:
//~   * `(xq2 - xr) * s3 = yq2 - yr`
//~   * `(2*xr - s3^2 + xq2) * ((xr - xs)*s3 + ys + yr) = (xr - xs) * 2*yr`
//~   * `(ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)`
//~ * Booleanity checks:
//~   * Bit flag $b_1$: `0 = b1 * (b1 - 1)`
//~   * Bit flag $b_2$: `0 = b2 * (b2 - 1)`
//~   * Bit flag $b_3$: `0 = b3 * (b3 - 1)`
//~   * Bit flag $b_4$: `0 = b4 * (b4 - 1)`
//~ * Binary decomposition:
//~   * Accumulated scalar: `n' = 16 * n + 8 * b1 + 4 * b2 + 2 * b3 + b4`
//~ * Distinct point checks:
//~   * `(xp - xr) * (xr - xs) * inv = 1`
//~     - Note: if `xp = xr` (equiv `xr = xs`) then we see `(yr + yp)^2 = 0`
//~       from constraint 3, and so we are necessarily in the disallowed
//~       degenerate case `P=-R` (`xp = xr` and `yr = -yp`).
//~
//~ Note: in the EC derivation below, `R` and `S` are local symbols inside each
//~ block's addition formulas. The witness columns still follow the row layout
//~ above (`xP, yP` as input, `xR, yR` after the first update, `xS, yS` after
//~ the second update).
//~
//~ The constraints above are derived from the following EC Affine arithmetic
//~ equations.
//~
//~ **Background on EC point addition/doubling:**
//~
//~ For points P = (x_p, y_p) and Q = (x_q, y_q) on a short Weierstrass curve,
//~ the sum R = P + Q = (x_r, y_r) is computed as:
//~
//~ * Slope: $s = (y_q - y_p) / (x_q - x_p)$
//~ * $x_r = s^2 - x_p - x_q$
//~ * $y_r = s \cdot (x_p - x_r) - y_p$
//~
//~ For point doubling R = 2P:
//~
//~ * Slope: $s = (3 x_p^2 + a) / (2 y_p)$ (where a=0 for our curves)
//~ * $x_r = s^2 - 2 \cdot x_p$
//~ * $y_r = s \cdot (x_p - x_r) - y_p$
//~
//~ **Derivation of the constraints:**
//~
//~ Each "block" computes S = (P + Q) + P where Q = (xq, yq) is determined by
//~ bits. The intermediate point R = P + Q and final point S = R + P.
//~
//~ We use two slopes:
//~ * $s_1$: slope for P + Q -> R
//~ * $s_2$: slope for R + P -> S
//~
//~ The key optimization is eliminating $s_2$ from the constraints by
//~ substituting:
//~
//~ * (1) => $(x_{q_1} - x_p) \cdot s_1 = y_{q_1} - y_p$
//~ * (2&3) => $(x_p – x_r) \cdot s_2 = y_r + y_p$
//~ * (2) => $(2 \cdot x_p + x_{q_1} – s_1^2) \cdot (s_1 + s_2) = 2 \cdot y_p$
//~   * <=> $(2 x_p - s_1^2 + x_{q_1})((x_p - x_r) s_1 + y_r + y_p)$
//~         $= (x_p - x_r) \cdot 2 y_p$
//~ * (3) => $s_1^2 - s_2^2 = x_{q_1} - x_r$
//~   * <=> $(y_r + y_p)^2 = (x_p – x_r)^2 \cdot (s_1^2 – x_{q_1} + x_r)$
//~ *
//~ * (4) => $(x_{q_2} - x_r) \cdot s_3 = y_{q_2} - y_r$
//~ * (5&6) => $(x_r – x_s) \cdot s_4 = y_s + y_r$
//~ * (5) => $(2 \cdot x_r + x_{q_2} – s_3^2) \cdot (s_3 + s_4) = 2 \cdot y_r$
//~   * <=> $(2 x_r - s_3^2 + x_{q_2})((x_r - x_s) s_3 + y_s + y_r)$
//~         $= (x_r - x_s) \cdot 2 y_r$
//~ * (6) => $s_3^2 – s_4^2 = x_{q_2} - x_s$
//~   * <=> $(y_s + y_r)^2 = (x_r – x_s)^2 \cdot (s_3^2 – x_{q_2} + x_s)$
//~
//~ Defining $s_2$ and $s_4$ as
//~
//~ * $s_2 := \frac{2 \cdot y_P}{2 * x_P + x_{q_1} - s_1^2} - s_1$
//~ * $s_4 := \frac{2 \cdot y_R}{2 * x_R + x_{q_2} - s_3^2} - s_3$
//~
//~ Gives the following equations when substituting $s_2$ and $s_4$:
//~
//~ 1. `(xq1 - xp) * s1 = yq1 - yp` (i.e., `(2 * b2 - 1) * yt - yp`)
//~ 2. `(2*xp - s1^2 + xq1) * ((xp - xr)*s1 + yr + yp) = (xp - xr) * 2*yp`
//~ 3. `(yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)`
//~
//~ 4. `(xq2 - xr) * s3 = yq2 - yr` (i.e., `(2 * b4 - 1) * yt - yr`)
//~ 5. `(2*xr - s3^2 + xq2) * ((xr - xs)*s3 + ys + yr) = (xr - xs) * 2*yr`
//~ 6. `(ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)`
//~

/// Implementation of group endomorphism optimized
/// variable base scalar multiplication custom Plonk constraints.
impl<F: PrimeField> CircuitGate<F> {
    pub fn create_endomul(wires: GateWires) -> Self {
        CircuitGate::new(GateType::EndoMul, wires, vec![])
    }

    /// Verify the `EndoMul` gate.
    ///
    /// # Errors
    ///
    /// Will give error if `self.typ` is not `GateType::EndoMul`, or if
    /// constraint evaluation fails.
    pub fn verify_endomul<
        const FULL_ROUNDS: usize,
        G: KimchiCurve<FULL_ROUNDS, ScalarField = F>,
    >(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(self.typ, GateType::EndoMul, "incorrect gate type");

        let this: [F; COLUMNS] = core::array::from_fn(|i| witness[i][row]);
        let next: [F; COLUMNS] = core::array::from_fn(|i| witness[i][row + 1]);

        let pt = F::from(123456u64);

        let constants = expr::Constants {
            mds: &G::sponge_params().mds,
            endo_coefficient: cs.endo,
            zk_rows: cs.zk_rows,
        };
        let challenges = BerkeleyChallenges {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: F::zero(),
        };

        let evals: ProofEvaluations<PointEvaluations<G::ScalarField>> =
            ProofEvaluations::dummy_with_witness_evaluations(this, next);

        let constraints = EndosclMul::constraints(&mut Cache::default());
        for (i, c) in constraints.iter().enumerate() {
            match c.evaluate_(cs.domain.d1, pt, &evals, &constants, &challenges) {
                Ok(x) => {
                    if x != F::zero() {
                        return Err(format!("Bad endo equation {i}"));
                    }
                }
                Err(e) => return Err(format!("evaluation failed: {e}")),
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

/// Implementation of the `EndosclMul` gate.
#[derive(Default)]
pub struct EndosclMul<F>(PhantomData<F>);

impl<F> Argument<F> for EndosclMul<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::EndoMul);
    const CONSTRAINTS: u32 = 12;

    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        cache: &mut Cache,
    ) -> Vec<T> {
        let b1 = env.witness_curr(11);
        let b2 = env.witness_curr(12);
        let b3 = env.witness_curr(13);
        let b4 = env.witness_curr(14);

        let xt = env.witness_curr(0);
        let yt = env.witness_curr(1);

        let inv = env.witness_curr(2);

        let xs = env.witness_next(4);
        let ys = env.witness_next(5);

        let xp = env.witness_curr(4);
        let yp = env.witness_curr(5);

        let xr = env.witness_curr(7);
        let yr = env.witness_curr(8);

        let s1 = env.witness_curr(9);
        let s3 = env.witness_curr(10);

        let endo_minus_1 = env.endo_coefficient() - T::one();
        let xq1 = cache.cache((T::one() + b1.clone() * endo_minus_1.clone()) * xt.clone());
        let xq2 = cache.cache((T::one() + b3.clone() * endo_minus_1) * xt);

        let yq1 = (b2.double() - T::one()) * yt.clone();
        let yq2 = (b4.double() - T::one()) * yt;

        let s1_squared = cache.cache(s1.square());
        let s3_squared = cache.cache(s3.square());

        // n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4
        let n = env.witness_curr(6);
        let n_next = env.witness_next(6);
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
            yr_yp.square() - (xp_xr.clone().square() * ((s1_squared - xq1) + xr.clone())),
            // (xq2 - xr) * s3 = yq2 - yr
            ((xq2.clone() - xr.clone()) * s3.clone()) - (yq2 - yr.clone()),
            // (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr - xs) * 2*yr
            (((xr.double() - s3_squared.clone()) + xq2.clone())
                * ((xr_xs.clone() * s3) + ys_yr.clone()))
                - (yr.double() * xr_xs.clone()),
            // (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)
            ys_yr.square() - (xr_xs.clone().square() * ((s3_squared - xq2) + xs)),
            n_constraint,
            // (xp - xr) * (xr - xs) * inv = 1
            xp_xr * xr_xs * inv - T::one(),
        ]
    }
}

/// The result of performing an endomorphism-optimized scalar multiplication.
///
/// After processing all scalar bits through the EndoMul gates, this struct
/// holds:
/// - The final accumulated curve point (as affine coordinates)
/// - The reconstructed scalar value from the processed bits
pub struct EndoMulResult<F> {
    /// The final accumulated point (x, y) after all scalar multiplication
    /// steps.
    /// This equals `[scalar]T` where `T` is the base point and `scalar` is
    /// derived from the input bits combined with the endomorphism.
    pub acc: (F, F),
    /// The accumulated scalar value reconstructed from all processed bits.
    /// For a 128-bit scalar processed in 32 rows (4 bits/row), this equals
    /// the original scalar k such that `acc = [k]T` (with endomorphism
    /// applied).
    pub n: F,
}

/// Generates the witness values for a series of EndoMul gates.
///
/// This function computes the witness for endomorphism-optimized scalar
/// multiplication. It processes 4 bits of the scalar per row, computing
/// the intermediate curve points and slopes needed for the constraints.
///
/// # Arguments
///
/// * `w` - The witness array to populate (15 columns x num_rows)
/// * `row0` - The starting row index
/// * `endo` - The endomorphism coefficient (cube root of unity in base field)
/// * `base` - The base point T = (x_T, y_T) being multiplied
/// * `bits` - Scalar bits in MSB-first order. Length must be a multiple of 4.
/// * `acc0` - Initial accumulator point. Typically set to `2*(T + phi(T))` to
///   avoid edge cases with the point at infinity.
///
/// # Returns
///
/// The final accumulated point and scalar after processing all bits.
///
/// # Wire Layout (per row)
///
/// | Col |  0  |  1  |  4  |  5  |  6  |  7  |  8  |  9  | 10  | 11  | 12  | 13  | 14  |
/// |-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|
/// |     | x_T | y_T | x_P | y_P |  n  | x_R | y_R | s1  | s3  | b1  | b2  | b3  | b4  |
///
/// # Panics
///
/// Will panic if `bits` length is not a multiple of 4.
pub fn gen_witness<F: Field + core::fmt::Display>(
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

    let bits: Vec<_> = bits.iter().map(|x| F::from(u64::from(*x))).collect();
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
        let xp_xr = xp - xr;
        let yr = xp_xr * s2 - yp;

        let xq2 = (one + (endo - one) * b3) * xt;
        let yq2 = (b4.double() - one) * yt;
        let s3 = (yq2 - yr) / (xq2 - xr);
        let s3_squared = s3.square();
        let s4 = yr.double() / (xr.double() + xq2 - s3_squared) - s3;

        let xs = xq2 + s4.square() - s3_squared;
        let xr_xs = xr - xs;
        let ys = xr_xs * s4 - yr;

        let inv = (xp_xr * xr_xs)
            .inverse()
            .expect("xr to be distinct from xp and xs");

        let row = i + row0;

        w[0][row] = base.0;
        w[1][row] = base.1;
        w[2][row] = inv;
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
