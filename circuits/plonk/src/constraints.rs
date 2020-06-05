/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{Evaluations, EvaluationDomain, Radix2EvaluationDomain as Domain, GeneralEvaluationDomain, DensePolynomial};
pub use super::gate::CircuitGate;
use rand_core::OsRng;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField>
{
    pub public: usize,                      // number of public inputs
    pub domain: Domain<F>,                  // evaluation domain
    pub gates:  Vec<CircuitGate<F>>,        // circuit gates

    // index polynomials over the monomial base
    pub sigmam: [DensePolynomial<F>; 3],    // permutation polynomial array
    pub ql:     DensePolynomial<F>,         // left input wire polynomial
    pub qr:     DensePolynomial<F>,         // right input wire polynomial
    pub qo:     DensePolynomial<F>,         // output wire polynomial
    pub qm:     DensePolynomial<F>,         // multiplication polynomial
    pub qc:     DensePolynomial<F>,         // constant wire polynomial

    pub sigmal: [Vec<F>; 3],                // permutation polynomial array over Lagrange base
    pub sid:    Vec<F>,                     // SID polynomial over Lagrange base
    pub r:      F,                          // coordinate shift for right wires
    pub o:      F,                          // coordinate shift for output wires
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    pub fn evals(v : Vec<F>, d : Domain<F>) -> Evaluations<F, GeneralEvaluationDomain<F>>
    {
        Evaluations::<F>::from_vec_and_domain(v, GeneralEvaluationDomain::Radix2(d))
    }

    pub fn evals_from_coeffs(&self, v : Vec<F>) -> Evaluations<F, GeneralEvaluationDomain<F>>
    {
        Evaluations::<F>::from_vec_and_domain(v, GeneralEvaluationDomain::Radix2(self.domain))
    }

    pub fn create
    (
        mut gates: Vec<CircuitGate<F>>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = Domain::<F>::new(Domain::<F>::compute_size_of_domain(gates.len())?)?;
        let sid = domain.elements().map(|elm| {elm}).collect::<Vec<_>>();
        let r =
        {
            let mut r = domain.sample_element_outside_domain(&mut OsRng);
            while r.legendre().is_qnr() == false {r = domain.sample_element_outside_domain(&mut OsRng)}
            r
        };
        let o =
        {
            let mut o = domain.sample_element_outside_domain(&mut OsRng);
            while o.legendre().is_qnr() == false || r==o {o = domain.sample_element_outside_domain(&mut OsRng)}
            o
        };

        let n = domain.size();
        gates.resize(n, CircuitGate::<F>::zero());

        let s =
        [
            sid.clone(),
            domain.elements().map(|elm| {r * &elm}).collect(),
            domain.elements().map(|elm| {o * &elm}).collect(),
        ];
        let mut sigmal = s.clone();

        gates.iter().for_each
        (
            |gate|
            {
                sigmal[0][gate.l.0] = s[gate.l.1 / n][gate.l.1 % n];
                sigmal[1][gate.r.0-n] = s[gate.r.1 / n][gate.r.1 % n];
                sigmal[2][gate.o.0-2*n] = s[gate.o.1 / n][gate.o.1 % n];
            }
        );

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmam:
            [
                Self::evals(sigmal[0].clone(), domain).interpolate(),
                Self::evals(sigmal[1].clone(), domain).interpolate(),
                Self::evals(sigmal[2].clone(), domain).interpolate(),
            ],
            sigmal,
            ql: Self::evals(gates.iter().map(|gate| gate.ql).collect(), domain).interpolate(),
            qr: Self::evals(gates.iter().map(|gate| gate.qr).collect(), domain).interpolate(),
            qo: Self::evals(gates.iter().map(|gate| gate.qo).collect(), domain).interpolate(),
            qm: Self::evals(gates.iter().map(|gate| gate.qm).collect(), domain).interpolate(),
            qc: Self::evals(gates.iter().map(|gate| gate.qc).collect(), domain).interpolate(),
            gates,
            r,
            o,
        })
    }
    
    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
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

    // utility function for efficient multiplication of several polys
    pub fn multiply(polys: &[&DensePolynomial<F>]) -> DensePolynomial<F>
    {
        for p in polys {if p.is_zero() {return DensePolynomial::<F>::zero()}}

        let domain = GeneralEvaluationDomain::new(polys.iter().map(|p| p.len()).fold(0, |x, y| x + &y)).
            expect("field is not smooth enough to construct domain");
        let evals = polys.iter().map
        (
            |p|
            {
                let mut e = p.evaluate_over_domain_by_ref(domain);
                e.evals.resize(domain.size(), F::zero());
                e
            }
        ).collect::<Vec<_>>();

        let evals = Evaluations::<F>::from_vec_and_domain
        (
            (0..domain.size()).map(|i| evals.iter().map(|e| e.evals[i]).fold(F::one(), |x, y| x * &y)).collect::<Vec<_>>(),
            domain
        );

        evals.interpolate()
    }
}
