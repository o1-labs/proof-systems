/*****************************************************************************************************************

This source file implements generic constraint polynomials.

*****************************************************************************************************************/

use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use crate::wires::GENERICS;
use algebra::{FftField, SquareRootField};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::utils::PolyUtils;

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// generic constraint quotient poly contribution computation
    pub fn gnrc_quot(
        &self,
        polys: &WitnessOverDomains<F>,
        public: &DensePolynomial<F>,
    ) -> (Evaluations<F, D<F>>, DensePolynomial<F>) {
        // w[0](x) * w[1](x) * qml(x)
        let multiplication = &(&polys.d4.this.w[0] * &polys.d4.this.w[1]) * &self.qml;
        // presence of left, right, and output wire
        // w[0](x) * qwl[0](x) + w[1](x) * qwl[1](x) + w[2](x) * qwl[2](x)
        let mut wires = self.zero4.clone();
        for (w, q) in polys.d4.this.w.iter().zip(self.qwl.iter()) {
            wires += &(w * q);
        }
        (&multiplication + &wires, &self.qc + &public)
    }

    pub fn gnrc_scalars(evals: &ProofEvaluations<F>) -> Vec<F> {
        let mut res = vec![evals.w[0] * &evals.w[1]];
        for i in 0..GENERICS {
            res.push(evals.w[i]);
        }
        // res = [l * r, l, r, o, 1]
        res.push(F::one()); // TODO(mimoo): this one is not used
        return res;
    }

    /// generic constraint linearization poly contribution computation
    pub fn gnrc_lnrz(&self, evals: &ProofEvaluations<F>) -> DensePolynomial<F> {
        let scalars = Self::gnrc_scalars(evals);
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
    use rand::SeedableRng;

    fn vanishing_polynomial_at(zeta: Fp, n: u64) -> Fp {
        zeta.pow(&[n]) - Fp::one()
    }

    #[test]
    fn test_generic_polynomial() {
        // create constraint system with a single generic gate
        let one = Fp::one();
        let zero = Fp::zero();
        let wires = array_init(|col| Wire { col, row: 0 });
        let gates = vec![CircuitGate::create_generic(
            0,
            wires,
            [one; COLUMNS],
            zero,
            zero,
        )];
        let cs = ConstraintSystem::fp_for_testing(gates);

        // random zeta
        let rng = &mut rand::rngs::StdRng::from_seed([0; 32]);
        let zeta = Fp::rand(rng);

        // compute quotient t(z) = f(z) / Z_H(z)
        /*
        let w = [DensePolynomial::zero(); COLUMNS];
        let z = DensePolynomial::zero(); // z does not matter here
        let lagrange = cs.evaluate(&w, &z);
        let public = DensePolynomial::zero();
        let generic_t = cs.gnrc_quot(&lagrange, &public);

        // compute linearization f(z)
        let scalars = gnrc_scalars(evals);
        let generic_f = gnrc_lnrz(evals);

        // check that f(z) = t(z) * Z_H(z)
        let z_h_zeta = vanishing_polynomial_at_zeta(zeta, cs.domain.d1.size);
        assert!(generic_f == generic_t * z_h_zeta);*/
    }
}
