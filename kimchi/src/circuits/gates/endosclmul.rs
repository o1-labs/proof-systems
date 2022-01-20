/*****************************************************************************************************************

This source file implements group endomorphism optimised
variable base scalar multiplication custom Plonk constraints.

EVBSM gate constraints
    b1*(b1-1) = 0
    b2*(b2-1) = 0
    b3*(b3-1) = 0
    b4*(b4-1) = 0
    ((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
    (2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
    ((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
    (2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
    (ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
    n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4

The constraints above are derived from the following EC Affine arithmetic equations:

    (xq1 - xp) * s1 = yq1 - yp
    (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)

    (xq2 - xr) * s3 = yq2 - yr
    (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
    (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)

*****************************************************************************************************************/

use crate::circuits::expr;
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::polynomials::endosclmul;
use crate::circuits::{
    nolookup::{constraints::ConstraintSystem, scalars::ProofEvaluations},
    wires::{GateWires, COLUMNS},
};
use ark_ff::FftField;
use array_init::array_init;

impl<F: FftField> CircuitGate<F> {
    pub fn create_endomul(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::EndoMul,
            wires,
            c: vec![],
        }
    }

    pub fn verify_endomul(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(self.typ, GateType::EndoMul, "incorrect gate type");

        let this: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);

        let pt = F::from(123456u64);

        let constants = expr::Constants {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: F::zero(),
            mds: vec![],
            endo_coefficient: cs.endo,
        };

        let evals: [ProofEvaluations<F>; 2] = [
            ProofEvaluations::dummy_with_witness_evaluations(this),
            ProofEvaluations::dummy_with_witness_evaluations(next),
        ];

        let constraints = endosclmul::constraints::<F>();
        for (i, c) in constraints.iter().enumerate() {
            match c.evaluate_(cs.domain.d1, pt, &evals, &constants) {
                Ok(x) => {
                    if x != F::zero() {
                        return Err(format!("Bad endo equation {}", i));
                    }
                }
                Err(e) => return Err(format!("evaluation failed: {}", e)),
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
