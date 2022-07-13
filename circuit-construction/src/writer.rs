use ark_ff::{BigInteger, FftField, PrimeField};
use array_init::array_init;
use kimchi::circuits::{
    gate::{CircuitGate, GateType},
    polynomials::generic::{
        DOUBLE_GENERIC_COEFFS, DOUBLE_GENERIC_REGISTERS, GENERIC_COEFFS, GENERIC_REGISTERS,
    },
    wires::{Wire, COLUMNS},
};
use oracle::{constants::*, permutation::full_round};
use std::collections::HashMap;

use crate::constants::Constants;

/// A variable in our circuit.
/// Variables are assigned with an index to differentiate from each other.
/// Optionally, they can eventually take as value a field element.
#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub struct Var<F> {
    pub index: usize,
    pub value: Option<F>,
}

impl<F: Copy> Var<F> {
    /// Returns the value inside a variable [Var].
    /// It panics if it is `None`.
    pub fn val(&self) -> F {
        self.value.unwrap()
    }
}

/// A variable that corresponds to scalar that is shifted by a certain amount.
pub struct ShiftedScalar<F>(Var<F>);

/// Specifies a gate within a circuit.
/// A gate will have a type,
/// will refer to a row of variables,
/// and will have associated vector of coefficients.
pub struct GateSpec<F> {
    pub typ: GateType,
    pub row: Vec<Option<Var<F>>>,
    pub coeffs: Vec<F>,
}

impl<F: FftField> GateSpec<F> {
    pub fn get_var_val_or(&self, col: usize, default: F) -> F {
        match self.row.get(col) {
            Some(Some(var)) => var.val(),
            _ => default,
        }
    }

    pub fn get_var_idx(&self, col: usize) -> Option<usize> {
        match self.row.get(col) {
            Some(Some(var)) => Some(var.index),
            _ => None,
        }
    }
}

/// A set of gates within the circuit.
/// It carries the index for the next available variable,
/// and the vector of [GateSpec] created so far.
/// It also keeps track of the queue of generic gates and cached constants.
#[derive(Default)]
pub struct System<F> {
    pub next_variable: usize,
    pub generic_gate_queue: Vec<GateSpec<F>>,
    // pub equivalence_classes: HashMap<Var, Vec<Position>>,
    pub gates: Vec<GateSpec<F>>,
    pub cached_constants: HashMap<F, Var<F>>,
}

/// Carries a vector of rows corresponding to the witness, a queue of generic gates, and stores the cached constants
#[derive(Default)]
pub struct WitnessGenerator<F>
where
    F: PrimeField,
{
    pub generic_gate_queue: Vec<GateSpec<F>>,
    pub rows: Vec<Row<F>>,
    pub cached_constants: HashMap<F, Var<F>>,
}

impl<F> WitnessGenerator<F>
where
    F: PrimeField,
{
    /// Given a list of public inputs, creates the witness generator.
    pub fn new(public_inputs: &[F]) -> Self {
        let mut gen = Self::default();

        for input in public_inputs {
            let row = array_init(|i| if i == 0 { *input } else { F::zero() });
            gen.rows.push(row);
        }

        gen
    }
}

/// A row is an array of [COLUMNS] elements
type Row<V> = [V; COLUMNS];

/// This trait includes all the operations that can be executed
/// by the elements in the circuits.
/// It allows for different behaviours depending on the struct for
/// which it is implemented for.
/// In particular, the circuit mode and the witness generation mode.
pub trait Cs<F: PrimeField> {
    /// In cases where you want to create a free variable in the circuit,
    /// as in the variable is not constrained _yet_
    /// and can be anything that the prover wants.
    /// For example, division can be implemented as:
    ///
    /// ```ignore
    /// let a = sys.constant(5u32.into());
    /// let b = sys.constant(10u32.into());
    /// let c = sys.var(|| {
    ///    b.value * a.value.inverse().unwrap()
    /// });
    /// sys.assert_eq(a * c, b);
    /// ```
    ///
    fn var<G>(&mut self, g: G) -> Var<F>
    where
        G: FnOnce() -> F;

    /// Returns the number of gates that the current [Self] contains.
    fn curr_gate_count(&self) -> usize;

    /// Returns a variable containing a field element as value that is
    /// computed as the equivalent `BigInteger` number returned by
    /// function `g`, only if the length is a multiple of 4.
    fn endo_scalar<G, N: BigInteger>(&mut self, length: usize, g: G) -> Var<F>
    where
        G: FnOnce() -> N,
    {
        assert_eq!(length % 4, 0);

        self.var(|| {
            let y = g();
            let bits = y.to_bits_le();
            F::from_repr(F::BigInt::from_bits_le(&bits)).unwrap()
        })
    }

    /// This function creates a [ShiftedScalar] variable from a field element that is
    /// returned by function `g()`, and a length that should be a multiple of 5.
    fn scalar<G, Fr: PrimeField>(&mut self, length: usize, g: G) -> ShiftedScalar<F>
    where
        G: FnOnce() -> Fr,
    {
        assert_eq!(length % 5, 0);

        let v = self.var(|| {
            // TODO: No need to recompute this each time.
            let two = Fr::from(2u64);
            let shift = Fr::one() + two.pow(&[length as u64]);

            let x = g();
            // x = 2 y + shift
            // y = (x - shift) / 2
            // TODO: Could cache value of 1/2 to avoid division
            let y = (x - shift) / two;
            let bits = y.into_repr().to_bits_le();
            F::from_repr(F::BigInt::from_bits_le(&bits)).unwrap()
        });
        ShiftedScalar(v)
    }

    /// In circuit mode, adds a gate to the circuit.
    /// In witness generation mode, adds the corresponding row to the witness.
    fn gate(&mut self, g: GateSpec<F>);

    /// Creates a `Generic` gate that constrains if two variables are equal.
    /// This is done by setting `x1` in the left wire and `x2` in the right wire
    /// with left coefficient `1` and right coefficient `-1`, so that `x1 - x2 = 0`.  
    // TODO: Optimize to use permutation argument.
    fn assert_eq(&mut self, x1: Var<F>, x2: Var<F>) {
        // | 0  | 1  | 2 | ...
        // | x1 | x2 | 0 | ...
        let vars = [Some(x1), Some(x2), None];

        // constrain `x1 - x2 = 0`
        let mut coeffs = [F::zero(); GENERIC_COEFFS];
        coeffs[0] = F::one();
        coeffs[1] = -F::one();

        self.generic(coeffs, vars);
    }

    /// Checks if a constant `x` is already in the cached constants of `self` and returns it.
    /// Otherwise, it creates a variable for it and caches it.
    fn cached_constants(&mut self, x: F) -> Var<F>;

    /// Creates a `Generic` gate to include a constant in the circuit, and returns the variable containing it.
    /// It sets the left wire to be the variable containing the constant `x` and the rest to zero.
    /// Then the left coefficient is set to one and the coefficient for constants is set to `-x`.
    /// This way, the constraint `1 * x - x = 0` holds.
    fn constant(&mut self, x: F) -> Var<F> {
        let v = self.cached_constants(x);

        let mut coeffs = [F::zero(); GENERIC_COEFFS];
        coeffs[0] = F::one();
        coeffs[GENERIC_REGISTERS + 1] = -x;

        let vars = [Some(v), None, None];

        self.generic(coeffs, vars);

        v
    }

    /// Stores a generic gate until it can combine two of them
    /// into a double generic gate.
    fn generic_queue(&mut self, gate: GateSpec<F>) -> Option<GateSpec<F>>;

    /// Adds a generic gate.
    ///
    /// Warning: this assumes that some finalization occurs to flush
    /// any queued generic gate.
    fn generic(&mut self, coeffs: [F; GENERIC_COEFFS], vars: [Option<Var<F>>; GENERIC_REGISTERS]) {
        let gate = GateSpec {
            typ: GateType::Generic,
            row: vars.to_vec(),
            coeffs: coeffs.to_vec(),
        };
        // we queue the single generic gate until we have two of them
        if let Some(double_generic_gate) = self.generic_queue(gate) {
            self.gate(double_generic_gate);
        }
    }

    /// Creates a `Generic` gate to constrain that a variable `v` is scaled by an `x` amount and returns it.
    /// First, it creates a new variable with a scaled value (meaning, the value in `v` times `x`).
    /// Then, it creates a row that sets the left wire to be `v` and the right wire to be the scaled variable.
    /// Finally, it sets the left coefficient to `x` and the right coefficient to `-1`.
    /// That way, the constraint `x * v - 1 * xv = 0` is created.
    fn scale(&mut self, x: F, v: Var<F>) -> Var<F> {
        let xv = self.var(|| v.val() * x);

        let vars = [Some(v), Some(xv), None];

        let mut coeffs = [F::zero(); GENERIC_COEFFS];
        coeffs[0] = x;
        coeffs[1] = -F::one();

        self.generic(coeffs, vars);

        xv
    }

    /// Performs curve point addition.
    /// It creates the corresponding `CompleteAdd` gate for the points `(x1, y1)` and `(x2,y2)`
    /// and returns the third point resulting from the addition as a tuple of variables.
    fn add_group(
        &mut self,
        zero: Var<F>,
        (x1, y1): (Var<F>, Var<F>),
        (x2, y2): (Var<F>, Var<F>),
    ) -> (Var<F>, Var<F>) {
        let mut same_x_bool = false;
        let same_x = self.var(|| {
            let same_x = x1.val() == x2.val();
            same_x_bool = same_x;
            F::from(same_x as u64)
        });

        let inf = zero;
        let x21_inv = self.var(|| {
            if x1.val() == x2.val() {
                F::zero()
            } else {
                (x2.val() - x1.val()).inverse().unwrap()
            }
        });

        let s = self.var(|| {
            if same_x_bool {
                let x1_squared = x1.val().square();
                (x1_squared.double() + x1_squared).div(y1.val().double())
            } else {
                (y2.val() - y1.val()) * x21_inv.val()
            }
        });

        let inf_z = self.var(|| {
            if y1.val() == y2.val() {
                F::zero()
            } else if same_x_bool {
                (y2.val() - y1.val()).inverse().unwrap()
            } else {
                F::zero()
            }
        });

        let x3 = self.var(|| s.val().square() - (x1.val() + x2.val()));

        let y3 = self.var(|| s.val() * (x1.val() - x3.val()) - y1.val());

        self.gate(GateSpec {
            typ: GateType::CompleteAdd,
            row: vec![
                Some(x1),
                Some(y1),
                Some(x2),
                Some(y2),
                Some(x3),
                Some(y3),
                Some(inf),
                Some(same_x),
                Some(s),
                Some(inf_z),
                Some(x21_inv),
            ],
            coeffs: vec![],
        });
        (x3, y3)
    }

    /// Doubles one curve point `(x1, y1)`, using internally the `add_group()` function.
    /// It creates a `CompleteAdd` gate for this point addition (with itself).
    /// Returns a tuple of variables corresponding to the doubled point.
    fn double(&mut self, zero: Var<F>, (x1, y1): (Var<F>, Var<F>)) -> (Var<F>, Var<F>) {
        self.add_group(zero, (x1, y1), (x1, y1))
    }

    /// Creates a `CompleteAdd` gate that checks whether a third point `(x3, y3)` is the addition
    /// of the two first points `(x1, y1)` and `(x2, y2)`.
    /// The difference between this function and `add_group()` is that in `assert_add_group` the
    /// third point is given, whereas in the other one it is computed with the formula.
    fn assert_add_group(
        &mut self,
        zero: Var<F>,
        (x1, y1): (Var<F>, Var<F>),
        (x2, y2): (Var<F>, Var<F>),
        (x3, y3): (Var<F>, Var<F>),
    ) {
        let mut same_x_bool = false;
        let same_x = self.var(|| {
            let same_x = x1.val() == x2.val();
            same_x_bool = same_x;
            F::from(same_x as u64)
        });

        let inf = zero;
        let x21_inv = self.var(|| {
            if x1.val() == x2.val() {
                F::zero()
            } else {
                (x2.val() - x1.val()).inverse().unwrap()
            }
        });

        let s = self.var(|| {
            if same_x_bool {
                let x1_squared = x1.val().square();
                (x1_squared.double() + x1_squared).div(y1.val().double())
            } else {
                (y2.val() - y1.val()) * x21_inv.val()
            }
        });

        let inf_z = self.var(|| {
            if y1.val() == y2.val() {
                F::zero()
            } else if same_x_bool {
                (y2.val() - y1.val()).inverse().unwrap()
            } else {
                F::zero()
            }
        });

        self.gate(GateSpec {
            typ: GateType::CompleteAdd,
            row: vec![
                Some(x1),
                Some(y1),
                Some(x2),
                Some(y2),
                Some(x3),
                Some(y3),
                Some(inf),
                Some(same_x),
                Some(s),
                Some(inf_z),
                Some(x21_inv),
            ],
            coeffs: vec![],
        });
    }

    /// This function is used to include conditionals in circuits.
    /// It creates three `Generic` gates to simulate the logics of the conditional.
    /// It receives as input:
    ///  - `b`: the branch
    ///  - `t`: the true
    ///  - `f`: the false
    /// And simulates the following equation: `res = b * ( t - f ) + f`
    /// ( when the condition is false, `res = 1` )
    /// ( when the condition is  true, `res = b` )
    /// This is constrained using three `Generic` gates
    /// 1. Constrain `delta = t - f`
    /// 2. Constrain `res1 = b * delta`
    /// 3. Constrain `res = res1 + f`
    /// For (1):
    /// - Creates a row with left wire `t`, right wire `f`, and output wire `delta`
    /// - Assigns `1` to the left coefficient, `-1` to the right coefficient, and `-1` to the output coefficient.
    /// - That way, it creates a first gate constraining: `1 * t - 1 * f - delta = 0``
    /// For (2):
    /// - Creates a row with left wire `b`, right wire `delta`, and output wire `res1`.
    /// - Assigns `-1` to the output coefficient, and `1` to the multiplication coefficient.
    /// - That way, it creates a second gate constraining: `-1 * res + 1 * b * delta = 0`
    /// For (3):
    /// - Creates a row with left wire `res1`, right wire `f`, and output wire `res`.
    /// - Assigns `1` to the left coefficient, `1` to the right coefficient, and `-1` to the output coefficient.
    /// - That way, it creates a third gate constraining: `1 * res1 + 1 * f - 1 * res = 0`
    fn cond_select(&mut self, b: Var<F>, t: Var<F>, f: Var<F>) -> Var<F> {
        // Could be more efficient. Currently uses three constraints :(
        // delta = t - f
        // res1 = b * delta
        // res = res1 + f

        let delta = self.var(|| t.val() - f.val());
        let res1 = self.var(|| b.val() * delta.val());
        let res = self.var(|| f.val() + res1.val());

        let row1 = [Some(t), Some(f), Some(delta)];
        let mut c1 = [F::zero(); GENERIC_COEFFS];
        c1[0] = F::one();
        c1[1] = -F::one();
        c1[2] = -F::one();

        self.generic(c1, row1);

        let row2 = [Some(b), Some(delta), Some(res1)];

        let mut c2 = [F::zero(); GENERIC_COEFFS];
        c2[0] = F::zero();
        c2[1] = F::zero();
        c2[2] = -F::one();
        c2[3] = F::one();

        self.generic(c2, row2);

        let row3 = [Some(res1), Some(f), Some(res)];
        let mut c3 = [F::zero(); GENERIC_COEFFS];
        c3[0] = F::one();
        c3[1] = F::one();
        c3[2] = -F::one();

        self.generic(c3, row3);

        res
    }

    /// Performs a scalar multiplication between a [ShiftedScalar] and a point `(xt, yt)`.
    /// This function creates 51 rows pairs of rows.
    fn scalar_mul(
        &mut self,
        zero: Var<F>,
        (xt, yt): (Var<F>, Var<F>),
        scalar: ShiftedScalar<F>,
    ) -> (Var<F>, Var<F>) {
        let num_bits = 255;
        let num_row_pairs = num_bits / 5;
        let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![]);

        let acc0 = self.add_group(zero, (xt, yt), (xt, yt));

        let _ = self.var(|| {
            witness = array_init(|_| vec![F::zero(); 2 * num_row_pairs]);
            // Creates a vector of bits from the value inside the scalar, with the most significant bit upfront
            let bits_msb: Vec<bool> = scalar
                .0
                .val()
                .into_repr()
                .to_bits_le()
                .iter()
                .take(num_bits)
                .copied()
                .rev()
                .collect();
            // Creates a witness for the VarBaseMul gate.
            kimchi::circuits::polynomials::varbasemul::witness(
                &mut witness,
                0,
                (xt.val(), yt.val()),
                &bits_msb,
                (acc0.0.val(), acc0.1.val()),
            );
            F::zero()
        });

        // For each of the pairs, it generates a VarBaseMul and a Zero gate.
        let mut res = None;
        for i in 0..num_row_pairs {
            let mut row1: [_; COLUMNS] = array_init(|j| self.var(|| witness[j][2 * i]));
            let row2: [_; COLUMNS] = array_init(|j| self.var(|| witness[j][2 * i + 1]));

            row1[0] = xt;
            row1[1] = yt;
            if i == 0 {
                row1[2] = acc0.0;
                row1[3] = acc0.1;
                row1[4] = zero;
            }
            if i == num_row_pairs - 1 {
                row1[5] = scalar.0;
                res = Some((row2[0], row2[1]));
            }

            self.gate(GateSpec {
                row: row1.into_iter().map(Some).collect(),
                typ: GateType::VarBaseMul,
                coeffs: vec![],
            });

            self.gate(GateSpec {
                row: row2.into_iter().map(Some).collect(),
                typ: GateType::Zero,
                coeffs: vec![],
            })
        }

        res.unwrap()
    }

    /// Creates an endoscalar multiplication gadget with `length_in_bits/4 + 1` gates.
    /// For each row, it adds one `EndoMul` gate. The gadget is finalized with a `Zero` gate.
    ///
    /// | row | `GateType` |
    /// | --- | ---------- |
    /// |  i  | `EndoMul`  |
    /// | i+1 | `EndoMul`  |
    /// | ... |    ...     |
    /// |  r  | `EndoMul`  |
    /// | r+1 | `Zero`     |
    ///
    fn endo(
        &mut self,
        zero: Var<F>,
        constants: &Constants<F>,
        (xt, yt): (Var<F>, Var<F>),
        scalar: Var<F>,
        length_in_bits: usize,
    ) -> (Var<F>, Var<F>) {
        let bits_per_row = 4;
        let rows = length_in_bits / 4;
        assert_eq!(0, length_in_bits % 4);

        let mut bits_ = vec![];
        let bits: Vec<_> = (0..length_in_bits)
            .map(|i| {
                self.var(|| {
                    if bits_.is_empty() {
                        bits_ = scalar
                            .val()
                            .into_repr()
                            .to_bits_le()
                            .iter()
                            .take(length_in_bits)
                            .copied()
                            .rev()
                            .collect()
                    }
                    F::from(bits_[i] as u64)
                })
            })
            .collect();

        let one = F::one();

        let endo = constants.endo;
        let mut acc = {
            let phip = (self.scale(endo, xt), yt);
            let phip_p = self.add_group(zero, phip, (xt, yt));
            self.double(zero, phip_p)
        };

        let mut n_acc = zero;

        // TODO: Could be more efficient
        for i in 0..rows {
            let b1 = bits[i * bits_per_row];
            let b2 = bits[i * bits_per_row + 1];
            let b3 = bits[i * bits_per_row + 2];
            let b4 = bits[i * bits_per_row + 3];

            let (xp, yp) = acc;

            let xq1 = self.var(|| (one + (endo - one) * b1.val()) * xt.val());
            let yq1 = self.var(|| (b2.val().double() - one) * yt.val());

            let s1 = self.var(|| (yq1.val() - yp.val()) / (xq1.val() - xp.val()));
            let s1_squared = self.var(|| s1.val().square());
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
            let s2 = self.var(|| {
                yp.val().double() / (xp.val().double() + xq1.val() - s1_squared.val()) - s1.val()
            });

            // (xr, yr)
            let xr = self.var(|| xq1.val() + s2.val().square() - s1_squared.val());
            let yr = self.var(|| (xp.val() - xr.val()) * s2.val() - yp.val());

            let xq2 = self.var(|| (one + (endo - one) * b3.val()) * xt.val());
            let yq2 = self.var(|| (b4.val().double() - one) * yt.val());
            let s3 = self.var(|| (yq2.val() - yr.val()) / (xq2.val() - xr.val()));
            let s3_squared = self.var(|| s3.val().square());
            let s4 = self.var(|| {
                yr.val().double() / (xr.val().double() + xq2.val() - s3_squared.val()) - s3.val()
            });

            let xs = self.var(|| xq2.val() + s4.val().square() - s3_squared.val());
            let ys = self.var(|| (xr.val() - xs.val()) * s4.val() - yr.val());

            self.gate(GateSpec {
                typ: GateType::EndoMul,
                row: vec![
                    Some(xt),
                    Some(yt),
                    None,
                    None,
                    Some(xp),
                    Some(yp),
                    Some(n_acc),
                    Some(xr),
                    Some(yr),
                    Some(s1),
                    Some(s3),
                    Some(b1),
                    Some(b2),
                    Some(b3),
                    Some(b4),
                ],
                coeffs: vec![],
            });

            acc = (xs, ys);

            n_acc = self.var(|| {
                let mut n_acc = n_acc.val();
                n_acc.double_in_place();
                n_acc += b1.val();
                n_acc.double_in_place();
                n_acc += b2.val();
                n_acc.double_in_place();
                n_acc += b3.val();
                n_acc.double_in_place();
                n_acc += b4.val();
                n_acc
            });
        }

        // TODO: use a generic gate with zero coeffs
        self.gate(GateSpec {
            typ: GateType::Zero,
            row: vec![
                None,
                None,
                None,
                None,
                Some(acc.0),
                Some(acc.1),
                Some(scalar),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            coeffs: vec![],
        });
        acc
    }

    /// Checks that a string of bits (with LSB first) correspond to the value inside variable `x`.
    /// It splits the bitstring across rows, where each row takes care of 8 crumbs of 2 bits each.
    ///
    fn assert_pack(&mut self, zero: Var<F>, x: Var<F>, bits_lsb: &[Var<F>]) {
        let crumbs_per_row = 8;
        let bits_per_row = 2 * crumbs_per_row;
        assert_eq!(bits_lsb.len() % bits_per_row, 0);
        let num_rows = bits_lsb.len() / bits_per_row;

        // Reverse string of bits to have MSB first in the vector
        let bits_msb: Vec<_> = bits_lsb.iter().rev().collect();

        let mut a = self.var(|| F::from(2u64));
        let mut b = self.var(|| F::from(2u64));
        let mut n = zero;

        let one = F::one();
        let neg_one = -one;

        // For each of the chunks, get the corresponding bits
        for (i, row_bits) in bits_msb[..].chunks(bits_per_row).enumerate() {
            let mut row: [Var<F>; COLUMNS] = array_init(|_| self.var(|| F::zero()));
            row[0] = n;
            row[2] = a;
            row[3] = b;

            // For this row, get crumbs of 2 bits each
            for (j, crumb_bits) in row_bits.chunks(2).enumerate() {
                // Remember the MSB of each crumb is in the 0 index
                let b0 = crumb_bits[1]; // less valued
                let b1 = crumb_bits[0]; // more valued

                // Value of the 2-bit crumb in MSB
                let crumb = self.var(|| b0.val() + b1.val().double());
                // Stores the 8 of them in positions [6..13] of the row
                row[6 + j] = crumb;

                a = self.var(|| {
                    let x = a.val().double();
                    if b1.val().is_zero() {
                        x
                    } else {
                        x + if b0.val().is_one() { one } else { neg_one }
                    }
                });

                b = self.var(|| {
                    let x = b.val().double();
                    if b1.val().is_zero() {
                        x + if b0.val().is_one() { one } else { neg_one }
                    } else {
                        x
                    }
                });

                // Accumulated chunk value
                n = self.var(|| n.val().double().double() + crumb.val());
            }

            // In final row, this is the input value, otherwise the accumulated value
            row[1] = if i == num_rows - 1 { x } else { n };
            row[4] = a;
            row[5] = b;

            row[14] = self.var(|| F::zero());
        }
    }

    /// Creates a Poseidon gadget for given constants and a given input.
    /// It generates a number of `Poseidon` gates followed by a final `Zero` gate.
    fn poseidon(&mut self, constants: &Constants<F>, input: Vec<Var<F>>) -> Vec<Var<F>> {
        use kimchi::circuits::polynomials::poseidon::*;

        let params = constants.poseidon;
        let rc = &params.round_constants;
        let width = PlonkSpongeConstantsKimchi::SPONGE_WIDTH;

        let mut states = vec![input];

        for row in 0..POS_ROWS_PER_HASH {
            let offset = row * ROUNDS_PER_ROW;

            for i in 0..ROUNDS_PER_ROW {
                let mut s: Option<Vec<F>> = None;
                states.push(
                    (0..3)
                        .map(|col| {
                            self.var(|| {
                                match &s {
                                    Some(s) => s[col],
                                    None => {
                                        // Do one full round on the previous value
                                        let mut acc = states[states.len() - 1]
                                            .iter()
                                            .map(|x| x.val())
                                            .collect();
                                        full_round::<F, PlonkSpongeConstantsKimchi>(
                                            params,
                                            &mut acc,
                                            offset + i,
                                        );
                                        let res = acc[col];
                                        s = Some(acc);
                                        res
                                    }
                                }
                            })
                        })
                        .collect(),
                );
            }

            self.gate(GateSpec {
                typ: kimchi::circuits::gate::GateType::Poseidon,
                coeffs: (0..COLUMNS)
                    .map(|i| rc[offset + (i / width)][i % width])
                    .collect(),
                row: vec![
                    Some(states[offset][0]),
                    Some(states[offset][1]),
                    Some(states[offset][2]),
                    Some(states[offset + 4][0]),
                    Some(states[offset + 4][1]),
                    Some(states[offset + 4][2]),
                    Some(states[offset + 1][0]),
                    Some(states[offset + 1][1]),
                    Some(states[offset + 1][2]),
                    Some(states[offset + 2][0]),
                    Some(states[offset + 2][1]),
                    Some(states[offset + 2][2]),
                    Some(states[offset + 3][0]),
                    Some(states[offset + 3][1]),
                    Some(states[offset + 3][2]),
                ],
            });
        }

        let final_state = &states[states.len() - 1];
        let final_row = vec![
            Some(final_state[0]),
            Some(final_state[1]),
            Some(final_state[2]),
        ];
        self.gate(GateSpec {
            typ: kimchi::circuits::gate::GateType::Zero,
            coeffs: vec![],
            row: final_row,
        });

        states.pop().unwrap()
    }
}

impl<F: PrimeField> Cs<F> for WitnessGenerator<F> {
    /// Creates a variable with value given by a function `g` with index `0`
    fn var<G>(&mut self, g: G) -> Var<F>
    where
        G: FnOnce() -> F,
    {
        Var {
            index: 0,
            value: Some(g()),
        }
    }

    /// Returns the number of rows.
    fn curr_gate_count(&self) -> usize {
        self.rows.len()
    }

    /// Pushes a new row corresponding to the values in the row of gate `g`.
    fn gate(&mut self, g: GateSpec<F>) {
        assert!(g.row.len() <= COLUMNS);

        let row: [F; COLUMNS] = array_init(|col| g.get_var_val_or(col, F::zero()));
        self.rows.push(row)
    }

    fn generic_queue(&mut self, gate: GateSpec<F>) -> Option<GateSpec<F>> {
        if let Some(mut other) = self.generic_gate_queue.pop() {
            other.row.extend(&gate.row);
            assert_eq!(other.row.len(), DOUBLE_GENERIC_REGISTERS);
            Some(other)
        } else {
            self.generic_gate_queue.push(gate);
            None
        }
    }

    fn cached_constants(&mut self, x: F) -> Var<F> {
        match self.cached_constants.get(&x) {
            Some(var) => *var,
            None => {
                let var = self.var(|| x);
                self.cached_constants.insert(x, var);
                var
            }
        }
    }
}

impl<F: PrimeField> WitnessGenerator<F> {
    /// Returns the columns of the witness.
    pub fn columns(&mut self) -> [Vec<F>; COLUMNS] {
        // flush any queued generic gate
        if let Some(gate) = self.generic_gate_queue.pop() {
            self.gate(gate);
        }

        // transpose
        array_init(|col| self.rows.iter().map(|row| row[col]).collect())
    }
}

impl<F: PrimeField> Cs<F> for System<F> {
    fn var<V>(&mut self, _: V) -> Var<F> {
        let v = self.next_variable;
        self.next_variable += 1;
        Var {
            index: v,
            value: None,
        }
    }

    /// Outputs the number of gates in the circuit
    fn curr_gate_count(&self) -> usize {
        self.gates.len()
    }

    fn gate(&mut self, g: GateSpec<F>) {
        self.gates.push(g);
    }

    fn generic_queue(&mut self, gate: GateSpec<F>) -> Option<GateSpec<F>> {
        if let Some(mut other) = self.generic_gate_queue.pop() {
            other.row.extend(&gate.row);
            assert_eq!(other.row.len(), DOUBLE_GENERIC_REGISTERS);
            other.coeffs.extend(&gate.coeffs);
            assert_eq!(other.coeffs.len(), DOUBLE_GENERIC_COEFFS);
            Some(other)
        } else {
            self.generic_gate_queue.push(gate);
            None
        }
    }

    fn cached_constants(&mut self, x: F) -> Var<F> {
        match self.cached_constants.get(&x) {
            Some(var) => *var,
            None => {
                let var = self.var(|| x);
                self.cached_constants.insert(x, var);
                var
            }
        }
    }
}

impl<F: PrimeField> System<F> {
    /// Compiles our intermediate representation into a circuit.
    pub fn gates(&mut self) -> Vec<CircuitGate<F>> {
        let mut first_cell: HashMap<usize, Wire> = HashMap::new();
        let mut most_recent_cell: HashMap<usize, Wire> = HashMap::new();
        let mut gates = vec![];

        // flush any queued generic gate
        if let Some(gate) = self.generic_gate_queue.pop() {
            self.gate(gate);
        }

        // convert GateSpec into CircuitGate
        for (row, gate) in self.gates.iter().enumerate() {
            // while tracking the wiring
            let wires = array_init(|col| {
                let curr = Wire { row, col };

                if let Some(index) = gate.get_var_idx(col) {
                    // wire this cell to the previous one
                    match most_recent_cell.insert(index, curr) {
                        Some(w) => w,
                        // unless it is the first cell,
                        // in which case we just save it for the very end
                        // (to complete the cycle)
                        None => {
                            first_cell.insert(index, curr);
                            curr
                        }
                    }
                } else {
                    // if no var to be found, it's a cell wired to itself
                    curr
                }
            });

            let g = CircuitGate {
                typ: gate.typ,
                wires,
                coeffs: gate.coeffs.clone(),
            };
            gates.push(g);
        }

        // finish the permutation cycle
        for (var, first) in first_cell.iter() {
            let last = *most_recent_cell.get(var).unwrap();
            gates[first.row].wires[first.col] = last;
        }

        gates
    }
}
