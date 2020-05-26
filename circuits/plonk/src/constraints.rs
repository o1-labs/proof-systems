/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{PrimeField, SquareRootField};
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

impl<F: PrimeField+SquareRootField> ConstraintSystem<F> 
{
    pub fn create
    (
        mut gates: Vec<CircuitGate<F>>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = EvaluationDomain::<F>::new(EvaluationDomain::<F>::compute_size_of_domain(gates.len())?)?;
        let sid = Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {elm}).collect(), domain);
        let r =
        {
            let mut r = domain.sample_element_outside_domain(&mut OsRng);
            while r.legendre().is_qnr() == false {r = domain.sample_element_outside_domain(&mut OsRng)}
            r
        };
        let o = r.square();

        let n = domain.size();
        gates.resize(n, CircuitGate::<F>::zero());

        let s =
        [
            sid.clone(),
            Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {r * &elm}).collect(), domain),
            Evaluations::<F>::from_vec_and_domain(domain.elements().map(|elm| {o * &elm}).collect(), domain),
        ];
        let mut sigma = s.clone();

        gates.iter().for_each
        (
            |gate|
            {
                sigma[0].evals[gate.l.0] = s[gate.l.1 / n].evals[gate.l.1 % n];
                sigma[1].evals[gate.r.0-n] = s[gate.r.1 / n].evals[gate.r.1 % n];
                sigma[2].evals[gate.o.0-2*n] = s[gate.o.1 / n].evals[gate.o.1 % n];
            }
        );

        Some(ConstraintSystem
        {
            domain,
            public,
            sigma,
            sid,
            ql: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.ql).collect(), domain),
            qr: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qr).collect(), domain),
            qo: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qo).collect(), domain),
            qm: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qm).collect(), domain),
            qc: Evaluations::<F>::from_vec_and_domain(gates.iter().map(|gate| gate.qc).collect(), domain),
            gates,
            r,
            o,
        })
    }
    
    // This function verifies the consistency of the wire assignements (witness)
    // against the constraints enforcing the public unput
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &mut self,
        witness: &Vec<F>
    ) -> bool
    {
        // verify witness against constraints
        if witness.len() != 3*self.domain.size() {return false}
        for gate in self.gates.iter().skip(self.public)
        {
            if
            !(
                gate.ql * &witness[gate.l.0] +
                &(gate.qr * &witness[gate.r.0]) +
                &(gate.qo * &witness[gate.o.0]) +
                &(gate.qm * &witness[gate.l.0] * &witness[gate.r.0]) +
                &gate.qc
            ).is_zero()
            ||
            !(
                gate.ql * &witness[gate.l.1] +
                &(gate.qr * &witness[gate.r.1]) +
                &(gate.qo * &witness[gate.o.1]) +
                &(gate.qm * &witness[gate.l.1] * &witness[gate.r.1]) +
                &gate.qc
            ).is_zero()
            {return false}
        }
        true
    }
}
