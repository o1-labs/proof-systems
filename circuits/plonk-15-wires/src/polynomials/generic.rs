/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::wires::GENERICS;
use crate::{nolookup::constraints::ConstraintSystem, polynomial::COLUMNS};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::Polynomial;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use oracle::utils::PolyUtils;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        witness_d4: &[Evaluations<F, D<F>>; COLUMNS],
        public: &DensePolynomial<F>,
    ) -> (Evaluations<F, D<F>>, DensePolynomial<F>) {
        // w[0](x) * w[1](x) * qml(x)
        let multiplication = &(&witness_d4[0] * &witness_d4[1]) * &self.qml;

        // presence of left, right, and output wire
        // w[0](x) * qwl[0](x) + w[1](x) * qwl[1](x) + w[2](x) * qwl[2](x)
        let mut wires = self.zero4.clone();
        for (w, q) in witness_d4.iter().zip(self.qwl.iter()) {
            wires += &(w * q);
        }

        // return in lagrange and monomial form for optimization purpose
        let eval_part = &multiplication + &wires;
        let poly_part = &self.qc + public;
        (eval_part, poly_part)
    }

    /// produces w[0](zeta) * w[1](zeta), w[0](zeta), w[1](zeta), w[2](zeta), 1
    pub fn gnrc_scalars(w_zeta: &[F; COLUMNS]) -> Vec<F> {
        let mut res = vec![w_zeta[0] * &w_zeta[1]];
        for i in 0..GENERICS {
            res.push(w_zeta[i]);
        }
        res.push(F::one()); // TODO(mimoo): this one shouldn't be here no?
        return res;
    }

    /// generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, w_zeta: &[F; COLUMNS]) -> DensePolynomial<F> {
        let scalars = Self::gnrc_scalars(w_zeta);

        // w[0](zeta) * qwm[0] + w[1](zeta) * qwm[1] + w[2](zeta) * qwm[2]
        let mut res = self
            .qwm
            .iter()
            .zip(scalars[1..].iter())
            .map(|(q, s)| q.scale(*s))
            .fold(DensePolynomial::<F>::zero(), |x, y| &x + &y);

        // multiplication
        res += &self.qmm.scale(scalars[0]);

        // constant selector
        res += &self.qc;

        // l * qwm[0] + r * qwm[1] + o * qwm[2] + l * r * qmm + qc
        res
    }

    /// function to verify the generic polynomials with a witness
    pub fn verify_generic(
        &self,
        witness: &[DensePolynomial<F>; COLUMNS],
        public: &DensePolynomial<F>,
    ) -> bool {
        // multiplication
        let multiplication = &(&witness[0] * &witness[1]) * &self.qmm;

        // addition (of left, right, output wires)
        if self.qwm.len() != GENERICS {
            return false;
        }
        let mut wires = DensePolynomial::zero();
        for (w, q) in witness.iter().zip(self.qwm.iter()) {
            wires += &(w * q);
        }

        // compute f
        let mut f = &multiplication + &wires;
        f += &self.qc;
        f += public;

        // verify that each row evaluates to zero
        let values: Vec<_> = witness
            .iter()
            .zip(self.qwl.iter())
            .map(|(w, q)| (w, q.interpolate_by_ref()))
            .collect();

        //
        for (row, elem) in self.domain.d1.elements().enumerate() {
            let qc = self.qc.evaluate(&elem);

            // qc check
            if qc != F::zero() {
                if -qc != values[0].0.evaluate(&elem) {
                    return false;
                }
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
                    self.qmm.evaluate(&elem),
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
    use crate::{
        gate::CircuitGate,
        wires::{Wire, COLUMNS},
    };

    use ark_ff::{UniformRand, Zero};
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
        gates.push(CircuitGate::create_generic_add(r, Wire::new(r))); // add
        let r = gates_row.next().unwrap();
        gates.push(CircuitGate::create_generic_mul(r, Wire::new(r))); // mul
        let r = gates_row.next().unwrap();
        gates.push(CircuitGate::create_generic_const(
            r,
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
        let (t1, t2) = cs.gnrc_quot(&witness_d4, &public);
        let t_before_division = &t1.interpolate() + &t2;
        let (t, rem) = t_before_division
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap();
        assert!(rem.is_zero());
        let t_zeta = t.evaluate(&zeta);

        // compute linearization f(z)
        let w_zeta: [Fp; COLUMNS] = array_init(|col| witness[col].evaluate(&zeta));
        let f = cs.gnrc_lnrz(&w_zeta);
        let f_zeta = f.evaluate(&zeta);

        // check that f(z) = t(z) * Z_H(z)
        let z_h_zeta = cs.domain.d1.evaluate_vanishing_polynomial(zeta);
        assert!(f_zeta == t_zeta * &z_h_zeta);
    }
}
