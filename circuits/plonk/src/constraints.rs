/*****************************************************************************************************************

This source file implements Plonk computation wire index primitive.

*****************************************************************************************************************/

use algebra::PrimeField;
use ff_fft::{Evaluations, EvaluationDomain};
pub use super::{gate::CircuitGate, witness::Witness};

#[derive(Clone)]
pub struct ConstraintSystem<F: PrimeField>
{
    // evaluation domains as multiplicative groups of roots of unity
    pub domain: EvaluationDomain<F>,
    pub gates:  Vec<CircuitGate<F>>,   // circuit gates

    //pub sigma:  [Evaluations<F>; 3],   // permutation polynomial array
    //pub sid:    Evaluations<F>,        // SID polynomial

    pub ql:     Evaluations<F>,        // left input wire polynomial
    pub qr:     Evaluations<F>,        // right input wire polynomial
    pub qo:     Evaluations<F>,        // output wire polynomial
    pub qm:     Evaluations<F>,        // multiplication polynomial
    pub qc:     Evaluations<F>,        // constant wire polynomial
}

impl<F: PrimeField> ConstraintSystem<F> 
{
    pub fn create (gates: &[CircuitGate<F>]) -> Option<Self>
    {
        let domain = EvaluationDomain::<F>::new(EvaluationDomain::<F>::compute_size_of_domain(gates.len())?)?;
        Some(ConstraintSystem
        {
            domain,
            gates: gates.to_vec(),
            ql: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.ql).collect(), domain),
            qr: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qr).collect(), domain),
            qo: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qo).collect(), domain),
            qm: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qm).collect(), domain),
            qc: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qc).collect(), domain),
        })
    }
    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Witness<F>
    ) -> bool
    {
        for i in 0..self.ql.evals.len()
        {
            if
            !(
                self.ql.evals[i] * &witness[self.gates[i].l] +
                &(self.qr.evals[i] * &witness[self.gates[i].r]) +
                &(self.qo.evals[i] * &witness[self.gates[i].o]) +
                &(self.qm.evals[i] * &witness[self.gates[i].l] * &witness[self.gates[i].r]) +
                &self.qc.evals[i]
            ).is_zero()
            {return false}
        }
        true
    }
}
