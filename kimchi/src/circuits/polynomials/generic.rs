//! This module implements Plonk generic constraint gate primitive.
//! The layout of the gate is the following:
//!
//! |  0 |  1 |  2 |  3 |  4 |  5 | 6 | 7 | 8 | 9 | 10 | 11 | 11 | 12 | 13 | 14 |
//! |:--:|:--:|:--:|:--:|:--:|:--:|:-:|:-:|:-:|:-:|:--:|:--:|:--:|:--:|:--:|:--:|
//! | l1 | r1 | o1 | l2 | r2 | o2 |   |   |   |   |    |    |    |    |    |    |
//!
//! where l1, r1, and o1 (resp. l2, r2, o2) are the
//! left, right, and output wires of the first (resp. second) generic gate.
//!
//! For the selector:
//!
//! |  0 |  1 |  2 |  3 |  4 |  5 | 6 | 7 | 8 | 9 | 10 | 11 | 11 | 12 | 13 | 14 |
//! |:--:|:--:|:--:|:--:|:--:|:--:|:-:|:-:|:-:|:-:|:--:|:--:|:--:|:--:|:--:|:--:|
//! | l1 | r1 | o1 | m1 | c1 | l2 | r2 | o2 | m2 | c2 |    |    |    |    |    |
//!
//! with m1 (resp. m2) the mul selector for the first (resp. second) gate,
//! and c1 (resp. c2) the constant selector for the first (resp. second) gate.
//!
//! The polynomial looks like this:
//!
//! <pre>
//! [
//!   alpha1 * (w0 * coeff0 + w1 * coeff1 + w2 * coeff2 + w0 * w1 * coeff3 + coeff4) +
//!   alpha2 * (w3 * coeff5 + w4 * coeff6 + w5 * coeff7 + w3 w4 coeff8 + coeff9)
//! ] * generic_selector
//! </pre>
//!

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, GateType},
    polynomial::COLUMNS,
    wires::{GateWires, GENERICS},
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use array_init::array_init;
use rayon::prelude::*;

//
// Constants
//

/// Number of constraints produced by the gate.
pub const CONSTRAINTS: usize = 1;

/// Offset for the second generic gate
pub const GENERICS_COEFFS: usize = GENERICS + 1 /* mul */ + 1 /* cst */;

//
// Gadgets
//

/// The different type of computation that are possible with a generic gate.
/// This type is useful to create a generic gate via the [create_generic_easy] function.
pub enum GenericGate<F> {
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
    /// This allows you to create two generic gates that will fit in one row, check [create_generic_easy] for a better to way to create these gates.
    pub fn create_generic(wires: GateWires, c: [F; GENERICS * 2 + 2 + 2]) -> Self {
        CircuitGate {
            typ: GateType::Generic,
            wires,
            coeffs: c.to_vec(),
        }
    }

    /// This allows you to create two generic gates by passing the desired
    /// `gate1` and `gate2` as two [GenericGate].
    pub fn create_generic_easy(
        wires: GateWires,
        gate1: GenericGate<F>,
        gate2: Option<GenericGate<F>>,
    ) -> Self {
        let mut coeffs = [F::zero(); GENERICS * 2 + 2 + 2];
        match gate1 {
            GenericGate::Add {
                left_coeff,
                right_coeff,
                output_coeff,
            } => {
                coeffs[0] = left_coeff.unwrap_or_else(F::one);
                coeffs[1] = right_coeff.unwrap_or_else(F::one);
                coeffs[2] = output_coeff.unwrap_or_else(|| -F::one());
            }
            GenericGate::Mul {
                output_coeff,
                mul_coeff,
            } => {
                coeffs[2] = output_coeff.unwrap_or_else(|| -F::one());
                coeffs[3] = mul_coeff.unwrap_or_else(F::one);
            }
            GenericGate::Const(cst) => {
                coeffs[0] = F::one();
                coeffs[4] = -cst;
            }
            GenericGate::Pub => {
                coeffs[0] = F::one();
            }
        };
        match gate2 {
            Some(GenericGate::Add {
                left_coeff,
                right_coeff,
                output_coeff,
            }) => {
                coeffs[5] = left_coeff.unwrap_or_else(F::one);
                coeffs[6] = right_coeff.unwrap_or_else(F::one);
                coeffs[7] = output_coeff.unwrap_or_else(|| -F::one());
            }
            Some(GenericGate::Mul {
                output_coeff,
                mul_coeff,
            }) => {
                coeffs[7] = output_coeff.unwrap_or_else(|| -F::one());
                coeffs[8] = mul_coeff.unwrap_or_else(F::one);
            }
            Some(GenericGate::Const(cst)) => {
                coeffs[5] = F::one();
                coeffs[9] = -cst;
            }
            Some(GenericGate::Pub) => {
                coeffs[5] = F::one();
                unimplemented!();
            }
            None => (),
        };
        Self::create_generic(wires, coeffs)
    }

    /// verifies that the generic gate constraints are solved by the witness
    pub fn verify_generic(&self, row: usize, witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        // assignments
        let this: [F; COLUMNS] = array_init(|i| witness[i][row]);

        // constants
        let zero = F::zero();

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Generic, "generic: incorrect gate");

        // toggling each column x[i] depending on the selectors c[i]
        let sum1 = (0..GENERICS)
            .map(|i| self.coeffs[i] * this[i])
            .fold(zero, |x, y| x + y);

        let sum2 = (0..GENERICS)
            .map(|i| self.coeffs[i + GENERICS_COEFFS] * this[i + GENERICS])
            .fold(zero, |x, y| x + y);

        // multiplication
        let mul1 = self.coeffs[3] * this[0] * this[1];
        let mul2 = self.coeffs[GENERICS_COEFFS + 3] * this[3] * this[4];

        ensure_eq!(
            zero,
            sum1 + mul1 + self.coeffs[4],
            "generic: incorrect first gate"
        );

        ensure_eq!(
            zero,
            sum2 + mul2 + self.coeffs[GENERICS_COEFFS + 4],
            "generic: incorrect second gate"
        );

        // TODO(mimoo): additional checks:
        // - if both left and right wire are set, then output must be set
        // - if constant wire is set, then left wire must be set

        // all good
        Ok(())
    }
}

// -------------------------------------------------

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        mut alphas: impl Iterator<Item = F>,
        witness_cols_d4: &[Evaluations<F, D<F>>; COLUMNS],
    ) -> Evaluations<F, D<F>> {
        // init
        let mut res1 = Evaluations::from_vec_and_domain(
            vec![F::zero(); self.domain.d4.size as usize],
            self.domain.d4,
        );
        let mut res2 = Evaluations::from_vec_and_domain(
            vec![F::zero(); self.domain.d4.size as usize],
            self.domain.d4,
        );

        let mut alpha1 = self.l04.clone();
        let mut alpha2 = self.l04.clone();

        let alpha = alphas
            .next()
            .expect("not enough powers of alpha for the generic gate");
        alpha1.evals.iter_mut().for_each(|x| *x *= &alpha);

        let alpha = alphas
            .next()
            .expect("not enough powers of alpha for the generic gate");
        alpha2.evals.iter_mut().for_each(|x| *x *= &alpha);

        // addition: L * selector_L + R * selector_R + O * selector_O
        for (witness_d4, selector_d8) in witness_cols_d4
            .iter()
            .zip(self.coefficients8.iter())
            .take(GENERICS)
        {
            res1.evals
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, eval)| *eval += witness_d4.evals[i] * selector_d8[2 * i])
        }

        for (w, coeff) in witness_cols_d4
            .iter()
            .skip(GENERICS)
            .zip(self.coefficients8.iter().skip(GENERICS_COEFFS))
            .take(GENERICS)
        {
            res2.evals
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, e)| *e += w.evals[i] * coeff[2 * i])
        }

        // + multiplication: left * right * selector
        let mut mul1 = &witness_cols_d4[0] * &witness_cols_d4[1];
        let mul_selector_d8 = &self.coefficients8[3];
        mul1.evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, eval)| *eval *= mul_selector_d8[2 * i]);
        res1 += &mul1;

        let mut mul2 = &witness_cols_d4[3] * &witness_cols_d4[4];
        let mul_selector_d8 = &self.coefficients8[GENERICS_COEFFS + 3];
        mul2.evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, eval)| *eval *= mul_selector_d8[2 * i]);
        res2 += &mul2;

        // + constant
        let constant_d8 = &self.coefficients8[4];
        res1.evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e += c[2 * i]);

        let constant_d8 = &self.coefficients8[GENERICS_COEFFS + 4];
        res2.evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e += constant_d8[2 * i]);

        // * generic selector
        let mut double_gate = &(&res1 * &alpha1) + &(&res2 * &alpha2);
        double_gate *= &self.generic4;

        // return the result
        double_gate
    }

    /// produces
    /// alpha * generic(zeta) * w[0](zeta) * w[1](zeta),
    /// alpha * generic(zeta) * w[0](zeta),
    /// alpha * generic(zeta) * w[1](zeta),
    /// alpha * generic(zeta) * w[2](zeta)
    pub fn gnrc_scalars(
        mut alphas: impl Iterator<Item = F>,
        w_zeta: &[F; COLUMNS],
        generic_zeta: F,
    ) -> Vec<F> {
        // setup
        let alpha1 = alphas
            .next()
            .expect("not enough alpha powers for generic gate");
        let alpha2 = alphas
            .next()
            .expect("not enough alpha powers for generic gate");
        let mut res = vec![];

        // pre-compute
        let alpha1_generic = alpha1 * generic_zeta;
        let alpha2_generic = alpha2 * generic_zeta;

        // addition:
        // - l(z) * generic(z) * alpha
        // - r(z) * generic(z) * alpha
        // - o(z) * generic(z) * alpha
        res.extend((0..GENERICS).map(|i| alpha1_generic * w_zeta[i]));
        // multiplication: l(z) * r(z) * generic(z) * alpha
        res.push(alpha1_generic * w_zeta[0] * w_zeta[1]);
        // constant
        res.push(alpha1_generic);

        // same for the second generic gate
        res.extend((GENERICS..(GENERICS * 2)).map(|i| alpha2_generic * w_zeta[i]));
        res.push(alpha2_generic * w_zeta[3] * w_zeta[4]);
        res.push(alpha2_generic);

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
        let n = d1.size as usize;

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

    /// Function to verify the generic polynomials with a witness.
    pub fn verify_generic(
        &self,
        witness: &[DensePolynomial<F>; COLUMNS],
        public: &DensePolynomial<F>,
    ) -> bool {
        // addition (of left, right, output wires)
        let coefficientsm: [_; COLUMNS] =
            array_init(|i| self.coefficients8[i].clone().interpolate());
        let mut ff = DensePolynomial::zero();
        for (w, q) in witness.iter().zip(&coefficientsm).take(GENERICS) {
            ff += &(w * q);
        }
        for (w, q) in witness
            .iter()
            .skip(GENERICS)
            .zip(coefficientsm.iter().skip(GENERICS_COEFFS))
            .take(GENERICS)
        {
            ff += &(w * q);
        }

        // multiplication
        ff += &(&(&witness[0] * &witness[1]) * &coefficientsm[3]);
        ff += &(&(&witness[3] * &witness[4]) * &coefficientsm[GENERICS_COEFFS + 3]);

        // constant
        ff += &coefficientsm[4];
        ff += &coefficientsm[GENERICS_COEFFS + 4];

        // note: no need to use the powers of alpha or the selector poly

        // public inputs
        ff += public;

        // verify that it is divisible by Z_H
        let (_t, res) = match ff.divide_by_vanishing_poly(self.domain.d1) {
            Some(x) => x,
            None => return false,
        };
        res.is_zero()
    }
}

// -------------------------------------------------

pub mod testing {
    use super::*;
    use crate::circuits::wires::Wire;
    use itertools::iterate;

    /// handy function to create a generic circuit
    pub fn create_circuit<F: FftField>(start_row: usize) -> Vec<CircuitGate<F>> {
        // create constraint system with a single generic gate
        let mut gates = vec![];

        // create generic gates
        let mut gates_row = iterate(start_row, |&i| i + 1);

        // add and mul
        for _ in 0..10 {
            let r = gates_row.next().unwrap();
            let g1 = GenericGate::Add {
                left_coeff: None,
                right_coeff: Some(3u32.into()),
                output_coeff: None,
            };
            let g2 = GenericGate::Mul {
                output_coeff: None,
                mul_coeff: Some(2u32.into()),
            };
            gates.push(CircuitGate::create_generic_easy(Wire::new(r), g1, Some(g2)));
        }

        // two consts
        for _ in 0..10 {
            let r = gates_row.next().unwrap();
            let g1 = GenericGate::Const(3u32.into());
            let g2 = GenericGate::Const(5u32.into());
            gates.push(CircuitGate::create_generic_easy(Wire::new(r), g1, Some(g2)));
        }

        gates
    }

    // handy function to fill in a witness created via [create_circuit]
    pub fn fill_in_witness<F: FftField>(start_row: usize, witness: &mut [Vec<F>; COLUMNS]) {
        // fill witness
        let mut witness_row = iterate(start_row, |&i| i + 1);

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
        let gates = testing::create_circuit::<Fp>(0);

        // create constraint system
        let cs = ConstraintSystem::fp_for_testing(gates);

        // create witness
        let n = cs.domain.d1.size();
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); n]);
        testing::fill_in_witness(0, &mut witness);

        // make sure we're done filling the witness correctly
        cs.verify(&witness).unwrap();

        // generate witness polynomials
        let witness_evals: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| Evaluations::from_vec_and_domain(witness[col].clone(), cs.domain.d1));
        let witness: [DensePolynomial<Fp>; COLUMNS] =
            array_init(|col| witness_evals[col].interpolate_by_ref());
        let witness_d4: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| witness[col].evaluate_over_domain_by_ref(cs.domain.d4));

        // make sure we've done that correctly
        let public = DensePolynomial::zero();
        //        assert!(cs.verify_generic(&witness, &public));

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
