//! This module implements generic constraint polynomials.

use crate::circuits::{
    constraints::ConstraintSystem,
    gates::generic::{CONSTANT_COEFF, MUL_COEFF},
    polynomial::COLUMNS,
    wires::GENERICS,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use rayon::prelude::*;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        mut alphas: impl Iterator<Item = F>,
        witness_cols_d4: &[Evaluations<F, D<F>>; COLUMNS],
    ) -> Evaluations<F, D<F>> {
        // multiplication: left * right
        let mut res_d4 = &witness_cols_d4[0] * &witness_cols_d4[1];

        // * multiplication selector
        let mul_selector_d8 = &self.coefficients8[MUL_COEFF];
        res_d4
            .evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, eval)| *eval *= mul_selector_d8[2 * i]);

        // + addition: L * selector_L + R * selector_R + O * selector_O
        for (witness_d4, selector_d8) in witness_cols_d4
            .iter()
            .zip(self.coefficients8.iter())
            .take(GENERICS)
        {
            res_d4
                .evals
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, eval)| *eval += witness_d4.evals[i] * selector_d8[2 * i])
        }

        // + constant
        let constant_d8 = &self.coefficients8[CONSTANT_COEFF];
        res_d4
            .evals
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e += constant_d8[2 * i]);

        // * generic selector
        res_d4 *= &self.generic4;

        // * alpha
        let alpha = alphas
            .next()
            .expect("not enough powers of alpha for the generic gate");
        let mut alpha4 = self.l04.clone();
        alpha4.evals.iter_mut().for_each(|x| *x *= alpha);
        res_d4 *= &alpha4;

        // return the result
        res_d4
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
    ) -> (Vec<F>, F) {
        let alpha = alphas
            .next()
            .expect("not enough alpha powers for generic gate");

        // multiplication: l(z) * r(z) * generic(z) * alpha
        let mut res = vec![alpha * generic_zeta * w_zeta[0] * w_zeta[1]];

        // addition:
        // - l(z) * generic(z) * alpha
        // - r(z) * generic(z) * alpha
        // - o(z) * generic(z) * alpha
        res.extend((0..GENERICS).map(|i| alpha * generic_zeta * w_zeta[i]));

        (res, alpha)
    }

    /// generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(
        &self,
        alphas: impl Iterator<Item = F>,
        w_zeta: &[F; COLUMNS],
        generic_zeta: F,
    ) -> Evaluations<F, D<F>> {
        let d1 = self.domain.d1;

        let (scalars, alpha) = Self::gnrc_scalars(alphas, w_zeta, generic_zeta);

        let n = d1.size as usize;

        let mut res = Evaluations::from_vec_and_domain(vec![F::zero(); n], d1);

        let scale = self.coefficients8[0].evals.len() / n;

        // w[0](zeta) * qwm[0] + w[1](zeta) * qwm[1] + w[2](zeta) * qwm[2]
        self.coefficients8
            .iter()
            .zip(scalars[1..].iter())
            .for_each(|(q, s)| {
                res.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
                    *e += *s * q.evals[scale * i];
                });
            });

        // multiplication
        let s = scalars[0];
        res.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
            *e += s * self.coefficients8[MUL_COEFF][scale * i];
        });

        // constant selector
        let alpha_generic_zeta = alpha * generic_zeta;
        res.evals.par_iter_mut().enumerate().for_each(|(i, e)| {
            *e += alpha_generic_zeta * self.coefficients8[CONSTANT_COEFF][scale * i];
        });

        res
    }

    /// function to verify the generic polynomials with a witness
    pub fn verify_generic(
        &self,
        witness: &[DensePolynomial<F>; COLUMNS],
        public: &DensePolynomial<F>,
    ) -> bool {
        // multiplication
        let coefficientsm: [_; COLUMNS] =
            array_init(|i| self.coefficients8[i].clone().interpolate());
        let multiplication = &(&witness[0] * &witness[1]) * &coefficientsm[MUL_COEFF];

        // addition (of left, right, output wires)
        let mut wires = DensePolynomial::zero();
        for (w, q) in witness.iter().zip(coefficientsm.iter()).take(GENERICS) {
            wires += &(w * q);
        }

        // compute f
        let mut f = &multiplication + &wires;
        f += &coefficientsm[CONSTANT_COEFF];
        f = &f * &self.genericm;
        f += public;

        // verify that each row evaluates to zero
        let values: Vec<_> = witness
            .iter()
            .zip(self.coefficients8.iter())
            .take(GENERICS)
            .map(|(w, q)| (w, q.interpolate_by_ref()))
            .collect();

        //
        for (row, elem) in self.domain.d1.elements().enumerate() {
            let qc = coefficientsm[CONSTANT_COEFF].evaluate(&elem);

            // qc check
            if qc != F::zero() && -qc != values[0].0.evaluate(&elem) {
                return false;
            }

            //
            let res = f.evaluate(&elem);
            if !res.is_zero() {
                for (col, (w, q)) in values.iter().enumerate() {
                    println!(
                        "  col {} | w = {} | q = {}",
                        col,
                        w.evaluate(&elem),
                        q.evaluate(&elem)
                    );
                }
                println!(
                    "  q_M = {} | mul = {}",
                    coefficientsm[MUL_COEFF].evaluate(&elem),
                    multiplication.evaluate(&elem)
                );
                println!("  q_C = {}", qc);
                println!("row {} of generic polynomial doesn't evaluate to zero", row);
                return false;
            }
        }

        // verify that it is divisible by Z_H (remove when that passes)
        let (_t, res) = match f.divide_by_vanishing_poly(self.domain.d1) {
            Some(x) => x,
            None => return false,
        };
        res.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::{
        gate::CircuitGate,
        wires::{Wire, COLUMNS},
    };
    use ark_ff::{One, UniformRand, Zero};
    use array_init::array_init;
    use itertools::iterate;
    use mina_curves::pasta::fp::Fp;
    use rand::SeedableRng;

    #[test]
    fn test_generic_polynomial() {
        // create constraint system with a single generic gate
        let mut gates = vec![];

        // create generic gates
        let mut gates_row = iterate(0usize, |&i| i + 1);
        let r = gates_row.next().unwrap();
        gates.push(CircuitGate::create_generic_add(
            Wire::new(r),
            Fp::one(),
            Fp::one(),
        )); // add
        let r = gates_row.next().unwrap();
        gates.push(CircuitGate::create_generic_mul(Wire::new(r))); // mul
        let r = gates_row.next().unwrap();
        gates.push(CircuitGate::create_generic_const(
            Wire::new(r),
            19u32.into(),
        )); // const

        // create constraint system
        let cs = ConstraintSystem::fp_for_testing(gates);

        // generate witness
        let n = cs.domain.d1.size();
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); n]);
        // fill witness
        let mut witness_row = iterate(0usize, |&i| i + 1);
        let left = 0;
        let right = 1;
        let output = 2;
        // add
        let r = witness_row.next().unwrap();
        witness[left][r] = 11u32.into();
        witness[right][r] = 23u32.into();
        witness[output][r] = 34u32.into();
        // mul
        let r = witness_row.next().unwrap();
        witness[left][r] = 5u32.into();
        witness[right][r] = 3u32.into();
        witness[output][r] = 15u32.into();
        // const
        let r = witness_row.next().unwrap();
        witness[left][r] = 19u32.into();

        // make sure we're done filling the witness correctly
        assert!(gates_row.next() == witness_row.next());
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
        assert!(cs.verify_generic(&witness, &public));

        // random zeta
        let rng = &mut rand::rngs::StdRng::from_seed([0; 32]);
        let zeta = Fp::rand(rng);

        // compute quotient by dividing with vanishing polynomial
        let alphas = vec![Fp::rand(rng)];
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
