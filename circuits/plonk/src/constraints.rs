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
    pub public: usize,                 // number of public inputs
    pub domain: EvaluationDomain<F>,   // evaluation domain
    pub gates:  Vec<CircuitGate<F>>,   // circuit gates

    // index polynomials over the Lagrange base
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
        g: &[CircuitGate<F>],
        public: usize,
    ) -> Option<Self>
    {
        // prepare the constraints for public imput
        let mut gates = (0..public).map
        (
            |i|
            {
                let mut gate = CircuitGate::<F>::zero();
                gate.ql = F::one();
                gate.l = i;
                gate
            }
        ).collect::<Vec<_>>();
        gates.extend(g.to_vec());

        let domain = EvaluationDomain::<F>::new(EvaluationDomain::<F>::compute_size_of_domain(gates.len())?)?;
        let sid = Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {elm}).collect(), domain);
        let r = domain.sample_element_outside_domain(&mut OsRng);
        let o = r.square();

        Some(ConstraintSystem
        {
            domain,
            public,
            gates: gates.to_vec(),
            sigma: // default identity permutation
            [
                sid.clone(),
                Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {r * &elm}).collect(), domain),
                Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {o * &elm}).collect(), domain),
            ],
            sid,
            ql: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.ql).collect(), domain),
            qr: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qr).collect(), domain),
            qo: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qo).collect(), domain),
            qm: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qm).collect(), domain),
            qc: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qc).collect(), domain),
            r,
            o,
        })
    }
    
    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &mut self,
        witness: &Vec<F>
    ) -> bool
    {
        // enforce public input
        (0..self.public).for_each(|i| self.qc.evals[i] = -witness[i]);

        // verify witness against constraints
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
