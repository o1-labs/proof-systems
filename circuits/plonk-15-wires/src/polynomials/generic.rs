/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use crate::wires::GENERICS;
use crate::{nolookup::constraints::ConstraintSystem, polynomial::COLUMNS};
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
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
        let poly_part = &self.qc + &public;
        let full_poly = &eval_part.interpolate_by_ref() + &poly_part;

        // verify that each row is 0 (remove when done)
        let values: Vec<_> = witness_d4
            .iter()
            .zip(self.qwl.iter())
            .map(|(w, q)| (w.interpolate_by_ref(), q.interpolate_by_ref()))
            .collect();
        let mul_gate_val = multiplication.interpolate_by_ref();
        let mul_gate = self.qml.interpolate_by_ref();
        for (row, elem) in self.domain.d1.elements().enumerate() {
            println!("row {}", row);
            for (col, (w, q)) in values.iter().enumerate() {
                println!(
                    "  col {} | w = {} | q = {}",
                    col,
                    w.evaluate(elem),
                    q.evaluate(elem)
                );
            }
            println!(
                "  q_M = {} | mul = {}",
                mul_gate.evaluate(elem),
                mul_gate_val.evaluate(elem)
            );
            let qc = self.qc.evaluate(elem);
            println!("  q_C = {}", qc);

            // qc check
            if qc != F::zero() {
                assert!(-qc == values[0].0.evaluate(elem));
            }

            //
            let res = full_poly.evaluate(elem);
            if !res.is_zero() {
                panic!("row {} of generic polynomial doesn't evaluate to zero", row);
            }
        }

        // verify that it is divisible by Z_H (remove when that passes)
        let (_t, res) = full_poly
            .divide_by_vanishing_poly(self.domain.d1)
            .expect("woot?");
        assert!(res.is_zero());

        //
        (eval_part, poly_part)
    }

    pub fn gnrc_scalars(w_zeta: &[F; COLUMNS]) -> Vec<F> {
        let mut res = vec![w_zeta[0] * &w_zeta[1]];
        for i in 0..GENERICS {
            res.push(w_zeta[i]);
        }
        // res = [l * r, l, r, o, 1]
        res.push(F::one()); // TODO(mimoo): this one is not used
        return res;
    }

    /// generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, w_zeta: &[F; COLUMNS]) -> DensePolynomial<F> {
        let scalars = Self::gnrc_scalars(w_zeta);
        // l * r * qmm + qc + l * qwm[0] + r * qwm[1] + o * qwm[2]
        &(&self.qmm.scale(scalars[0]) + &self.qc)
            + &self
                .qwm
                .iter()
                .zip(scalars[1..].iter())
                .map(|(q, s)| q.scale(*s))
                .fold(DensePolynomial::<F>::zero(), |x, y| &x + &y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gate::CircuitGate,
        wires::{Wire, COLUMNS},
    };
    use algebra::{pasta::fp::Fp, Field, One, UniformRand, Zero};
    use array_init::array_init;
    use itertools::iterate;
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

        // make sure we're done filling the witness
        assert!(gates_row.next() == witness_row.next());

        // generate witness polynomials
        let witness_evals: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| Evaluations::from_vec_and_domain(witness[col].clone(), cs.domain.d1));
        let witness: [DensePolynomial<Fp>; COLUMNS] =
            array_init(|col| witness_evals[col].interpolate_by_ref());
        let witness_d4: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| witness[col].evaluate_over_domain_by_ref(cs.domain.d4));

        // random zeta
        let rng = &mut rand::rngs::StdRng::from_seed([0; 32]);
        let zeta = Fp::rand(rng);

        // compute quotient by dividing with vanishing polynomial
        let public = DensePolynomial::zero();
        let (t1, t2) = cs.gnrc_quot(&witness_d4, &public);
        let t_before_division = &t1.interpolate() + &t2;
        let (t, rem) = t_before_division
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap();
        assert!(rem.is_zero());
        let t_zeta = t.evaluate(zeta);

        // compute linearization f(z)
        let w_zeta: [Fp; COLUMNS] = array_init(|col| witness[col].evaluate(zeta));
        let f = cs.gnrc_lnrz(&w_zeta);
        let f_zeta = f.evaluate(zeta);

        // check that f(z) = t(z) * Z_H(z)
        let z_h_zeta = cs.domain.d1.evaluate_vanishing_polynomial(zeta);
        assert!(f_zeta == t_zeta * &z_h_zeta);
    }
}
