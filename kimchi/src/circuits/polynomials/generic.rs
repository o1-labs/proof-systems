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

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, GateType},
    polynomial::COLUMNS,
    wires::GateWires,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use array_init::array_init;
use rayon::prelude::*;

/// Number of constraints produced by the gate.
pub const CONSTRAINTS: u32 = 2;

/// Number of generic of registers by a single generic gate
pub const GENERIC_REGISTERS: usize = 3;

/// Number of coefficients used by a single generic gate
/// Three are used for the registers, one for the multiplication,
/// and one for the constant.
pub const GENERIC_COEFFS: usize = GENERIC_REGISTERS + 1 /* mul */ + 1 /* cst */;

/// The different type of computation that are possible with a generic gate.
/// This type is useful to create a generic gate via the [CircuitGate::create_generic_gadget] function.
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
}

impl<F: FftField> CircuitGate<F> {
    /// This allows you to create two generic gates that will fit in one row, check [Self::create_generic_gadget] for a better to way to create these gates.
    pub fn create_generic(wires: GateWires, c: [F; GENERIC_COEFFS * 2]) -> Self {
        CircuitGate {
            typ: GateType::Generic,
            wires,
            coeffs: c.to_vec(),
        }
    }

    /// This allows you to create two generic gates by passing the desired
    /// `gate1` and `gate2` as two [GenericGateSpec].
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
            None => (),
        };
        Self::create_generic(wires, coeffs)
    }
}

// -------------------------------------------------

//~ The constraints:
//~
//~ * $w_0 \cdot c_0 + w_1 \cdot c_1 + w_2 \cdot c_2 + w_0 \cdot w_1 \cdot c_3 + c_4$
//~ * $w_3 \cdot c_5 + w_4 \cdot c_6 + w_5 \cdot c_7 + w_3 w_4 c_8 + c_9$
//~
//~ where the $c_i$ are the [coefficients]().

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        mut alphas: impl Iterator<Item = F>,
        witness_cols_d4: &[Evaluations<F, D<F>>; COLUMNS],
    ) -> Evaluations<F, D<F>> {
        let generic_gate = |alpha_pow, coeff_offset, register_offset| {
            let mut res = Evaluations::from_vec_and_domain(
                vec![F::zero(); self.domain.d4.size()],
                self.domain.d4,
            );

            // addition
            for (witness_d4, selector_d8) in witness_cols_d4
                .iter()
                .skip(register_offset)
                .zip(self.coefficients8.iter().skip(coeff_offset))
                .take(GENERIC_REGISTERS)
            {
                res.evals
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, eval)| *eval += witness_d4.evals[i] * selector_d8[2 * i])
            }

            // multiplication
            let mut mul = &witness_cols_d4[register_offset] * &witness_cols_d4[register_offset + 1];
            let mul_selector_d8 = &self.coefficients8[coeff_offset + 3];
            mul.evals
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, eval)| *eval *= mul_selector_d8[2 * i]);
            res += &mul;

            // constant
            let constant_d8 = &self.coefficients8[coeff_offset + 4];
            res.evals
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, e)| *e += constant_d8[2 * i]);

            // alpha
            let alpha_pow = {
                let mut res = self.precomputations().constant_1_d4.clone();
                res.evals.par_iter_mut().for_each(|x| *x *= &alpha_pow);
                res
            };

            &res * &alpha_pow
        };

        let alpha_pow1 = alphas
            .next()
            .expect("not enough powers of alpha for the generic gate");
        let mut res = generic_gate(alpha_pow1, 0, 0);

        let alpha_pow2 = alphas
            .next()
            .expect("not enough powers of alpha for the generic gate");
        res += &generic_gate(alpha_pow2, GENERIC_COEFFS, GENERIC_REGISTERS);

        // generic selector
        &res * &self.generic4
    }

    /// produces
    ///
    /// ```ignore
    /// alpha * generic(zeta) * w[0](zeta) * w[1](zeta),
    /// alpha * generic(zeta) * w[0](zeta),
    /// alpha * generic(zeta) * w[1](zeta),
    /// alpha * generic(zeta) * w[2](zeta)
    /// ```
    pub fn gnrc_scalars(
        mut alphas: impl Iterator<Item = F>,
        w_zeta: &[F; COLUMNS],
        generic_zeta: F,
    ) -> Vec<F> {
        // setup
        let mut res = vec![];

        let mut generic_gate = |alpha_pow, register_offset| {
            let alpha_generic = alpha_pow * generic_zeta;

            // addition
            res.push(alpha_generic * w_zeta[register_offset]);
            res.push(alpha_generic * w_zeta[register_offset + 1]);
            res.push(alpha_generic * w_zeta[register_offset + 2]);

            // multplication
            res.push(alpha_generic * w_zeta[register_offset] * w_zeta[register_offset + 1]);

            // constant
            res.push(alpha_generic);
        };

        let alpha_pow1 = alphas
            .next()
            .expect("not enough alpha powers for generic gate");
        generic_gate(alpha_pow1, 0);

        let alpha_pow2 = alphas
            .next()
            .expect("not enough alpha powers for generic gate");
        generic_gate(alpha_pow2, GENERIC_REGISTERS);

        res
    }

    /// generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(
        &self,
        alphas: impl Iterator<Item = F>,
        w_zeta: &[F; COLUMNS],
        generic_zeta: F,
    ) -> Evaluations<F, D<F>> {
        let d1 = self.domain.d1;
        let n = d1.size();

        // get scalars
        let scalars = Self::gnrc_scalars(alphas, w_zeta, generic_zeta);

        //
        let mut res = Evaluations::from_vec_and_domain(vec![F::zero(); n], d1);

        let scale = self.coefficients8[0].evals.len() / n;

        let coeffs = self.coefficients8.iter();
        for (scalar, coeff) in scalars.into_iter().zip(coeffs) {
            res.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                *e += scalar * coeff[scale * i];
            });
        }

        // l * qwm[0] + r * qwm[1] + o * qwm[2] + l * r * qmm + qc
        res
    }
}

// -------------------------------------------------

pub mod testing {
    use super::*;
    use crate::circuits::wires::Wire;
    use itertools::iterate;

    impl<F: FftField> CircuitGate<F> {
        /// verifies that the generic gate constraints are solved by the witness
        pub fn verify_generic(
            &self,
            row: usize,
            witness: &[Vec<F>; COLUMNS],
            public: &[F],
        ) -> Result<(), String> {
            // assignments
            let this: [F; COLUMNS] = array_init(|i| witness[i][row]);

            // constants
            let zero = F::zero();

            // check if it's the correct gate
            ensure_eq!(self.typ, GateType::Generic, "generic: incorrect gate");

            let check_single = |coeffs_offset, register_offset| {
                let sum = self.coeffs[coeffs_offset] * this[register_offset]
                    + self.coeffs[coeffs_offset + 1] * this[register_offset + 1]
                    + self.coeffs[coeffs_offset + 2] * this[register_offset + 2];
                let mul = self.coeffs[coeffs_offset + 3]
                    * this[register_offset]
                    * this[register_offset + 1];
                let public = if coeffs_offset == 0 {
                    public.get(row).cloned().unwrap_or_else(F::zero)
                } else {
                    F::zero()
                };
                ensure_eq!(
                    zero,
                    sum + mul + self.coeffs[coeffs_offset + 4] - public,
                    "generic: incorrect gate"
                );
                Ok(())
            };

            check_single(0, 0)?;
            check_single(GENERIC_COEFFS, GENERIC_REGISTERS)
        }
    }

    impl<F: FftField + SquareRootField> ConstraintSystem<F> {
        /// Function to verify the generic polynomials with a witness.
        pub fn verify_generic(
            &self,
            witness: &[DensePolynomial<F>; COLUMNS],
            public: &DensePolynomial<F>,
        ) -> bool {
            let coefficientsm: [_; COLUMNS] =
                array_init(|i| self.coefficients8[i].clone().interpolate());

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
            res = &res * &self.genericm;

            // verify that it is divisible by Z_H
            match res.divide_by_vanishing_poly(self.domain.d1) {
                Some((_quotient, rest)) => rest.is_zero(),
                None => false,
            }
        }
    }

    /// function to create a generic circuit
    pub fn create_circuit<F: FftField>(start_row: usize, public: usize) -> Vec<CircuitGate<F>> {
        // create constraint system with a single generic gate
        let mut gates = vec![];

        // create generic gates
        let mut gates_row = iterate(start_row, |&i| i + 1);

        // public input
        for _ in 0..public {
            let r = gates_row.next().unwrap();
            gates.push(CircuitGate::create_generic_gadget(
                Wire::new(r),
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
                Wire::new(r),
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
                Wire::new(r),
                g1,
                Some(g2),
            ));
        }

        gates
    }

    // function to fill in a witness created via [create_circuit]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::wires::COLUMNS;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{EvaluationDomain, Polynomial};
    use array_init::array_init;
    use mina_curves::pasta::fp::Fp;
    use rand::SeedableRng;

    #[test]
    fn test_generic_polynomial() {
        // create circuit
        let gates = testing::create_circuit::<Fp>(0, 0);

        // create constraint system
        let cs = ConstraintSystem::fp_for_testing(gates);

        // create witness
        let n = cs.domain.d1.size();
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); n]);
        testing::fill_in_witness(0, &mut witness, &[]);

        // make sure we're done filling the witness correctly
        cs.verify(&witness, &[]).unwrap();

        // generate witness polynomials
        let witness_evals: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| Evaluations::from_vec_and_domain(witness[col].clone(), cs.domain.d1));
        let witness: [DensePolynomial<Fp>; COLUMNS] =
            array_init(|col| witness_evals[col].interpolate_by_ref());
        let witness_d4: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| witness[col].evaluate_over_domain_by_ref(cs.domain.d4));

        // make sure we've done that correctly
        let public = DensePolynomial::zero();
        assert!(cs.verify_generic(&witness, &public));

        // random zeta
        let rng = &mut rand::rngs::StdRng::from_seed([0; 32]);
        let zeta = Fp::rand(rng);

        // compute quotient by dividing with vanishing polynomial
        let alphas = vec![Fp::rand(rng), Fp::rand(rng)];
        let t1 = cs.gnrc_quot(&mut alphas.clone().into_iter(), &witness_d4);
        let t_before_division = &t1.interpolate() + &public;
        let (t, rem) = t_before_division
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap();
        assert!(rem.is_zero());
        let t_zeta = t.evaluate(&zeta);

        // compute linearization f(z)
        let w_zeta: [Fp; COLUMNS] = array_init(|col| witness[col].evaluate(&zeta));
        let generic_zeta = cs.genericm.evaluate(&zeta);

        let f = cs
            .gnrc_lnrz(&mut alphas.clone().into_iter(), &w_zeta, generic_zeta)
            .interpolate();
        let f_zeta = f.evaluate(&zeta);

        // check that f(z) = t(z) * Z_H(z)
        let z_h_zeta = cs.domain.d1.evaluate_vanishing_polynomial(zeta);
        assert!(f_zeta == t_zeta * z_h_zeta);
    }
}
