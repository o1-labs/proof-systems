/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::PrimeField;
use ff_fft::{Evaluations, EvaluationDomain};
pub use super::gate::CircuitGate;
use rand_core::OsRng;

#[derive(Clone)]
pub struct ConstraintSystem<F: PrimeField>
{
    // evaluation domains as multiplicative groups of roots of unity
    pub domain: EvaluationDomain<F>,
    pub gates:  Vec<CircuitGate<F>>,   // circuit gates

    pub sigma:  [Evaluations<F>; 3],   // permutation polynomial array
    pub sid:    Evaluations<F>,        // SID polynomial

    pub ql:     Evaluations<F>,        // left input wire polynomial
    pub qr:     Evaluations<F>,        // right input wire polynomial
    pub qo:     Evaluations<F>,        // output wire polynomial
    pub qm:     Evaluations<F>,        // multiplication polynomial
    pub qc:     Evaluations<F>,        // constant wire polynomial

    pub r:      F,                     // coordinate shift for right wires
    pub o:      F,                     // coordinate shift for output wires
}

impl<F: PrimeField> ConstraintSystem<F> 
{
    pub fn create
    (
        gates: &[CircuitGate<F>],
    ) -> Option<Self>
    {
        let domain = EvaluationDomain::<F>::new(EvaluationDomain::<F>::compute_size_of_domain(gates.len()+2)?)?;
        let sid = Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {elm}).collect(), domain);
        let tmp = Evaluations::<F>::from_vec_and_domain(Vec::new(), domain);
        let r = domain.sample_element_outside_domain(&mut OsRng);

        Some(ConstraintSystem
        {
            domain,
            gates: gates.to_vec(),
            sigma: [tmp.clone(), tmp.clone(), tmp],
            sid,
            ql: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.ql).collect(), domain),
            qr: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qr).collect(), domain),
            qo: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qo).collect(), domain),
            qm: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qm).collect(), domain),
            qc: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qc).collect(), domain),
            o: r.square(),
            r,
        })
    }
    
    // This function recomputes constraints enforcing public inputs
    pub fn public(&mut self)
    {
        self.qc = Evaluations::<F>::from_vec_and_domain(self.gates.iter().map(|gate| gate.qc).collect(), self.domain);
    }
    
    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Vec<F>
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
