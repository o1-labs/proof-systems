//! This module implements the double generic gate.

//~ The double generic gate contains two generic gates.
//~
//~ A generic gate is simply the 2-fan in gate specified in the
//~ vanilla PLONK protocol that allows us to do operations like:
//~
//~ * addition of two registers (into an output register)
//~ * or multiplication of two registers
//~ * equality of a register with a constant
//~
//~ More generally, the generic gate controls the coefficients $c_i$ in the equation:
//~
//~ $$c_0 \cdot l + c_1 \cdot r + c_2 \cdot o + c_3 \cdot (l \times r) + c_4$$
//~
//~ The layout of the gate is the following:
//~
//~ |  0 |  1 |  2 |  3 |  4 |  5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
//~ |:--:|:--:|:--:|:--:|:--:|:--:|:-:|:-:|:-:|:-:|:--:|:--:|:--:|:--:|:--:|
//~ | l1 | r1 | o1 | l2 | r2 | o2 |   |   |   |   |    |    |    |    |    |
//~
//~ where l1, r1, and o1 (resp. l2, r2, o2)
//~ are the left, right, and output registers
//~ of the first (resp. second) generic gate.
//~
//~ The selectors are stored in the coefficient table as:
//~
//~ |  0 |  1 |  2 |  3 |  4 |  5 | 6  |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
//~ |:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
//~ | l1 | r1 | o1 | m1 | c1 | l2 | r2 | o2 | m2 | c2 |    |    |    |    |    |
//~
//~ with m1 (resp. m2) the mul selector for the first (resp. second) gate,
//~ and c1 (resp. c2) the constant selector for the first (resp. second) gate.
//~

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        berkeley_columns::BerkeleyChallengeTerm,
        expr::{constraints::ExprOps, Cache},
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::GateWires,
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use core::{array, marker::PhantomData};
use poly_commitment::OpenProof;

/// Number of constraints produced by the gate.
pub const CONSTRAINTS: u32 = 2;

/// Number of generic of registers by a single generic gate
pub const GENERIC_REGISTERS: usize = 3;

/// Number of coefficients used by a single generic gate
/// Three are used for the registers, one for the multiplication,
/// and one for the constant.
pub const GENERIC_COEFFS: usize = GENERIC_REGISTERS + 1 /* mul */ + 1 /* cst */;

/// The double generic gate actually contains two generic gates.
pub const DOUBLE_GENERIC_COEFFS: usize = GENERIC_COEFFS * 2;

/// Number of generic of registers by a double generic gate.
pub const DOUBLE_GENERIC_REGISTERS: usize = GENERIC_REGISTERS * 2;

/// Implementation of the `Generic` gate
#[derive(Default)]
pub struct Generic<F>(PhantomData<F>);

impl<F> Argument<F> for Generic<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Generic);
    const CONSTRAINTS: u32 = 2;

    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        // First generic gate
        let left_coeff1 = env.coeff(0);
        let right_coeff1 = env.coeff(1);
        let out_coeff1 = env.coeff(2);
        let mul_coeff1 = env.coeff(3);
        let constant1 = env.coeff(4);
        let left1 = env.witness_curr(0);
        let right1 = env.witness_curr(1);
        let out1 = env.witness_curr(2);

        let constraint1 = left_coeff1 * left1.clone()
            + right_coeff1 * right1.clone()
            + out_coeff1 * out1
            + mul_coeff1 * left1 * right1
            + constant1;

        // Second generic gate
        let left_coeff2 = env.coeff(5);
        let right_coeff2 = env.coeff(6);
        let out_coeff2 = env.coeff(7);
        let mul_coeff2 = env.coeff(8);
        let constant2 = env.coeff(9);
        let left2 = env.witness_curr(3);
        let right2 = env.witness_curr(4);
        let out2 = env.witness_curr(5);

        let constraint2 = left_coeff2 * left2.clone()
            + right_coeff2 * right2.clone()
            + out_coeff2 * out2
            + mul_coeff2 * left2 * right2
            + constant2;

        vec![constraint1, constraint2]
    }
}

/// The different type of computation that are possible with a generic gate.
/// This type is useful to create a generic gate via the [`CircuitGate::create_generic_gadget`] function.
#[derive(Clone)]
pub enum GenericGateSpec<F> {
    /// Add two values.
    Add {
        /// Optional coefficient that can be multiplied with the left operand.
        left_coeff: Option<F>,
        /// Optional coefficient that can be multiplied with the right operand.
        right_coeff: Option<F>,
        /// Optional coefficient that can be multiplied with the output.
        output_coeff: Option<F>,
    },
    /// Multiplication of two values
    Mul {
        /// Optional coefficient that can be multiplied with the output.
        output_coeff: Option<F>,
        /// Optional coefficient that can be multiplied with the multiplication result.
        mul_coeff: Option<F>,
    },
    /// A constant, the constructor contains the constant itself
    Const(F),
    /// A public gate
    Pub,
    /// Sum a value to a constant
    Plus(F),
}

impl<F: PrimeField> CircuitGate<F> {
    /// This allows you to create two generic gates that will fit in one row, check [`Self::create_generic_gadget`] for a better to way to create these gates.
    pub fn create_generic(wires: GateWires, c: [F; GENERIC_COEFFS * 2]) -> Self {
        CircuitGate::new(GateType::Generic, wires, c.to_vec())
    }

    /// This allows you to create two generic gates by passing the desired
    /// `gate1` and `gate2` as two [`GenericGateSpec`].
    pub fn create_generic_gadget(
        wires: GateWires,
        gate1: GenericGateSpec<F>,
        gate2: Option<GenericGateSpec<F>>,
    ) -> Self {
        let mut coeffs = [F::zero(); GENERIC_COEFFS * 2];
        match gate1 {
            GenericGateSpec::Add {
                left_coeff,
                right_coeff,
                output_coeff,
            } => {
                coeffs[0] = left_coeff.unwrap_or_else(F::one);
                coeffs[1] = right_coeff.unwrap_or_else(F::one);
                coeffs[2] = output_coeff.unwrap_or_else(|| -F::one());
            }
            GenericGateSpec::Mul {
                output_coeff,
                mul_coeff,
            } => {
                coeffs[2] = output_coeff.unwrap_or_else(|| -F::one());
                coeffs[3] = mul_coeff.unwrap_or_else(F::one);
            }
            GenericGateSpec::Const(cst) => {
                coeffs[0] = F::one();
                coeffs[4] = -cst;
            }
            GenericGateSpec::Pub => {
                coeffs[0] = F::one();
            }
            GenericGateSpec::Plus(cst) => {
                coeffs[0] = F::one();
                coeffs[1] = F::zero();
                coeffs[2] = -F::one();
                coeffs[3] = F::zero();
                coeffs[4] = cst;
            }
        };
        match gate2 {
            Some(GenericGateSpec::Add {
                left_coeff,
                right_coeff,
                output_coeff,
            }) => {
                coeffs[5] = left_coeff.unwrap_or_else(F::one);
                coeffs[6] = right_coeff.unwrap_or_else(F::one);
                coeffs[7] = output_coeff.unwrap_or_else(|| -F::one());
            }
            Some(GenericGateSpec::Mul {
                output_coeff,
                mul_coeff,
            }) => {
                coeffs[7] = output_coeff.unwrap_or_else(|| -F::one());
                coeffs[8] = mul_coeff.unwrap_or_else(F::one);
            }
            Some(GenericGateSpec::Const(cst)) => {
                coeffs[5] = F::one();
                coeffs[9] = -cst;
            }
            Some(GenericGateSpec::Pub) => {
                coeffs[5] = F::one();
                unimplemented!();
            }
            Some(GenericGateSpec::Plus(cst)) => {
                coeffs[5] = F::one();
                coeffs[6] = F::zero();
                coeffs[7] = -F::one();
                coeffs[8] = F::zero();
                coeffs[9] = cst;
            }
            None => (),
        };
        Self::create_generic(wires, coeffs)
    }

    pub fn extend_generic(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        wires: GateWires,
        gate1: GenericGateSpec<F>,
        gate2: Option<GenericGateSpec<F>>,
    ) {
        let gate = Self::create_generic_gadget(wires, gate1, gate2);
        *curr_row += 1;
        gates.extend_from_slice(&[gate]);
    }
}

// -------------------------------------------------

//~ The constraints:
//~
//~ * $w_0 \cdot c_0 + w_1 \cdot c_1 + w_2 \cdot c_2 + w_0 \cdot w_1 \cdot c_3 + c_4$
//~ * $w_3 \cdot c_5 + w_4 \cdot c_6 + w_5 \cdot c_7 + w_3 w_4 c_8 + c_9$
//~
//~ where the $c_i$ are the `coefficients`.

// -------------------------------------------------

pub mod testing {
    use super::*;
    use crate::circuits::wires::Wire;
    use itertools::iterate;

    impl<F: PrimeField> CircuitGate<F> {
        /// verifies that the generic gate constraints are solved by the witness
        ///
        /// # Errors
        ///
        /// Will give error if `self.typ` is not `GateType::Generic`.
        pub fn verify_generic(
            &self,
            row: usize,
            witness: &[Vec<F>; COLUMNS],
            public: &[F],
        ) -> Result<(), String> {
            // assignments
            let this: [F; COLUMNS] = array::from_fn(|i| witness[i][row]);

            // constants
            let zero = F::zero();

            // check if it's the correct gate
            ensure_eq!(self.typ, GateType::Generic, "generic: incorrect gate");

            let check_single = |coeffs_offset, register_offset| {
                let get = |offset| {
                    self.coeffs
                        .get(offset)
                        .copied()
                        .unwrap_or_else(|| F::zero())
                };
                let l_coeff = get(coeffs_offset);
                let r_coeff = get(coeffs_offset + 1);
                let o_coeff = get(coeffs_offset + 2);
                let m_coeff = get(coeffs_offset + 3);
                let c_coeff = get(coeffs_offset + 4);

                let sum = l_coeff * this[register_offset]
                    + r_coeff * this[register_offset + 1]
                    + o_coeff * this[register_offset + 2];
                let mul = m_coeff * this[register_offset] * this[register_offset + 1];
                let public = if coeffs_offset == 0 {
                    public.get(row).copied().unwrap_or_else(F::zero)
                } else {
                    F::zero()
                };
                ensure_eq!(
                    zero,
                    sum + mul + c_coeff - public,
                    "generic: incorrect gate"
                );
                Ok(())
            };

            check_single(0, 0)?;
            check_single(GENERIC_COEFFS, GENERIC_REGISTERS)
        }
    }

    impl<F: PrimeField, G: KimchiCurve<ScalarField = F>, OpeningProof: OpenProof<G>>
        ProverIndex<G, OpeningProof>
    {
        /// Function to verify the generic polynomials with a witness.
        pub fn verify_generic(
            &mut self,
            witness: &[DensePolynomial<F>; COLUMNS],
            public: &DensePolynomial<F>,
        ) -> bool {
            let coefficientsm: [_; COLUMNS] = array::from_fn(|i| {
                self.column_evaluations.get().coefficients8[i]
                    .clone()
                    .interpolate()
            });

            let generic_gate = |coeff_offset, register_offset| {
                // addition (of left, right, output wires)
                let mut ff = &coefficientsm[coeff_offset] * &witness[register_offset];
                ff += &(&coefficientsm[coeff_offset + 1] * &witness[register_offset + 1]);
                ff += &(&coefficientsm[coeff_offset + 2] * &witness[register_offset + 2]);

                // multiplication
                ff += &(&(&witness[register_offset] * &witness[register_offset + 1])
                    * &coefficientsm[coeff_offset + 3]);

                // constant
                &ff + &coefficientsm[coeff_offset + 4]

                // note: skip alpha power, as we're testing for completeness
            };

            let mut res = generic_gate(0, 0);
            res += &generic_gate(GENERIC_COEFFS, GENERIC_REGISTERS);

            // public inputs
            res += public;

            // selector poly
            res = &res
                * &self
                    .column_evaluations
                    .get()
                    .generic_selector4
                    .interpolate_by_ref();
            // Interpolation above is inefficient, as is the rest of the function,
            // would be better just to check the equation on all the rows.

            // verify that it is divisible by Z_H
            match res.divide_by_vanishing_poly(self.cs.domain.d1) {
                Some((_quotient, rest)) => rest.is_zero(),
                None => false,
            }
        }
    }

    /// Create a generic circuit
    ///
    /// # Panics
    ///
    /// Will panic if `gates_row` is None.
    pub fn create_circuit<F: PrimeField>(start_row: usize, public: usize) -> Vec<CircuitGate<F>> {
        // create constraint system with a single generic gate
        let mut gates = vec![];

        // create generic gates
        let mut gates_row = iterate(start_row, |&i| i + 1);

        // public input
        for _ in 0..public {
            let r = gates_row.next().unwrap();
            gates.push(CircuitGate::create_generic_gadget(
                Wire::for_row(r),
                GenericGateSpec::Pub,
                None,
            ));
        }

        // add and mul
        for _ in 0..10 {
            let r = gates_row.next().unwrap();
            let g1 = GenericGateSpec::Add {
                left_coeff: None,
                right_coeff: Some(3u32.into()),
                output_coeff: None,
            };
            let g2 = GenericGateSpec::Mul {
                output_coeff: None,
                mul_coeff: Some(2u32.into()),
            };
            gates.push(CircuitGate::create_generic_gadget(
                Wire::for_row(r),
                g1,
                Some(g2),
            ));
        }

        // two consts
        for _ in 0..10 {
            let r = gates_row.next().unwrap();
            let g1 = GenericGateSpec::Const(3u32.into());
            let g2 = GenericGateSpec::Const(5u32.into());
            gates.push(CircuitGate::create_generic_gadget(
                Wire::for_row(r),
                g1,
                Some(g2),
            ));
        }

        gates
    }

    /// Fill in a witness created via [`create_circuit`]
    ///
    /// # Panics
    ///
    /// Will panic if `witness_row` is None.
    pub fn fill_in_witness<F: FftField>(
        start_row: usize,
        witness: &mut [Vec<F>; COLUMNS],
        public: &[F],
    ) {
        // fill witness
        let mut witness_row = iterate(start_row, |&i| i + 1);

        // public
        for p in public {
            let r = witness_row.next().unwrap();
            witness[0][r] = *p;
        }

        // add and mul
        for _ in 0..10 {
            let r = witness_row.next().unwrap();

            witness[0][r] = 11u32.into();
            witness[1][r] = 23u32.into();
            witness[2][r] = (11u32 + 23u32 * 3u32).into();

            witness[3][r] = 11u32.into();
            witness[4][r] = 23u32.into();
            witness[5][r] = (11u32 * 23 * 2).into();
        }

        // const
        for _ in 0..10 {
            let r = witness_row.next().unwrap();

            witness[0][r] = 3u32.into();

            witness[3][r] = 5u32.into();
        }
    }
}
