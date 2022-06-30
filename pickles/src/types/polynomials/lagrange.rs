use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use ark_poly::EvaluationDomain;

use circuit_construction::{generic, Cs, Var};

use super::{VanishEval, VarEval};

use crate::util::var_sum;

pub struct LagrangePoly<F: FftField + PrimeField> {
    evals: Vec<Var<F>>,
}

impl<F: FftField + PrimeField> LagrangePoly<F> {
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    // evaluates a lagrange polynomial at
    //
    // see: https://o1-labs.github.io/proof-systems/kimchi/lagrange.html
    pub fn eval<C: Cs<F>>(&self, cs: &mut C, x: Var<F>, pnt: &VanishEval<F>) -> VarEval<F, 1> {
        assert!(self.evals.len() > 0);
        assert!(self.evals.len() as u64 <= pnt.domain.size);

        // L_i(X) = Z_H(X) / (m * (X - g^i))

        // iterate over evaluation pairs (xi, yi)
        let mut terms = vec![];
        for (gi, yi) in pnt.domain.elements().zip(self.evals.iter().cloned()) {
            // compute g^i
            let m = pnt.domain.size_as_field_element;

            // The lagrange polynomial time yi can be evaluated using a single generic gate.
            // (since only x and yi are variable).
            //
            // Define:
            //
            // liyi = yi * L_i(x) / Z_H(x)
            // yi times the i'th lagrange poly L_i evaluated at x, except the multiplication by Z_H(x).
            //
            // Rewrite:
            //
            // 1. [liyi] = ([yi] * gi) / (m * [x] - m gi)
            // 2. [liyi] * (m * [x] - m g^i) = [yi] * gi
            // 3. [liyi] * (m * [x] - m g^i) = [yi] * gi
            terms.push(generic!(
                cs,
                (x, yi) : { ? * (m*x - m*gi) = yi*gi }
            ));
        }

        // compute sum and muliply bu Z_H(x)
        let sum = var_sum(cs, terms.into_iter());
        cs.mul(sum, pnt.as_ref().clone()).into()
    }

    pub fn size(&self) -> usize {
        self.evals.len()
    }
}
