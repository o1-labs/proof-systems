/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{EvaluationDomain, DensePolynomial};
pub use super::gate::{CircuitGate, SPONGE_WIDTH};
pub use super::domains::EvaluationDomains;
use array_init::array_init;
use rand_core::OsRng;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField>
{
    pub public: usize,                      // number of public inputs
    pub domain: EvaluationDomains<F>,       // evaluation domains
    pub gates:  Vec<CircuitGate<F>>,        // circuit gates

    // index polynomials over the monomial base
    pub sigmam: [DensePolynomial<F>; 3],    // permutation polynomial array

    // generic selector polynomials
    pub ql:     DensePolynomial<F>,         // left input wire polynomial
    pub qr:     DensePolynomial<F>,         // right input wire polynomial
    pub qo:     DensePolynomial<F>,         // output wire polynomial
    pub qm:     DensePolynomial<F>,         // multiplication polynomial
    pub qc:     DensePolynomial<F>,         // constant wire polynomial

    // poseidon selector polynomials
    pub rc:     [DensePolynomial<F>; SPONGE_WIDTH], // round constant polynomials
    
    // index polynomials over Lagrange base
    pub sigmal: [Vec<F>; 3],                // permutation polynomial array
    pub sid:    Vec<F>,                     // SID polynomial
    pub pbox:   Vec<F>,                     // poseidon indicator evaluations over domain.dp
    pub p2:     Vec<F>,                     // poseidon indicator 1-w evaluations over domain.d2

    pub r:      F,                          // coordinate shift for right wires
    pub o:      F,                          // coordinate shift for output wires
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> 
{
    pub fn create
    (
        mut gates: Vec<CircuitGate<F>>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = EvaluationDomains::<F>::create(gates.len())?;
        let mut sid = domain.d1.elements().map(|elm| {elm}).collect::<Vec<_>>();

        // sample the coordinate shifts
        let r =
        {
            let mut r = domain.d1.sample_element_outside_domain(&mut OsRng);
            while r.legendre().is_qnr() == false {r = domain.d1.sample_element_outside_domain(&mut OsRng)}
            r
        };
        let o =
        {
            let mut o = domain.d1.sample_element_outside_domain(&mut OsRng);
            while o.legendre().is_qnr() == false || r==o {o = domain.d1.sample_element_outside_domain(&mut OsRng)}
            o
        };

        let n = domain.d1.size();
        gates.resize(n, CircuitGate::<F>::zero());

        let s =
        [
            sid.clone(),
            domain.d1.elements().map(|elm| {r * &elm}).collect(),
            domain.d1.elements().map(|elm| {o * &elm}).collect(),
        ];
        let mut sigmal = s.clone();

        // compute permutation polynomials
        gates.iter().for_each
        (
            |gate|
            {
                sigmal[0][gate.l.0] = s[gate.l.1 / n][gate.l.1 % n];
                sigmal[1][gate.r.0-n] = s[gate.r.1 / n][gate.r.1 % n];
                sigmal[2][gate.o.0-2*n] = s[gate.o.1 / n][gate.o.1 % n];
            }
        );

        let mut s = sid[0..3].to_vec();
        sid.append(&mut s);

        // compute poseidon constraint polynomials
        let mut pm = EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.ip).collect(), domain.d1).interpolate();
        let pbox = EvaluationDomains::evals_from_coeffs(pm.coeffs.clone(), domain.dp).evals;
        pm = &DensePolynomial::from_coefficients_slice(&[F::one()]) - &pm;

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmam:
            [
                EvaluationDomains::evals_from_coeffs(sigmal[0].clone(), domain.d1).interpolate(),
                EvaluationDomains::evals_from_coeffs(sigmal[1].clone(), domain.d1).interpolate(),
                EvaluationDomains::evals_from_coeffs(sigmal[2].clone(), domain.d1).interpolate(),
            ],
            sigmal,
            ql: EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.ql).collect(), domain.d1).interpolate(),
            qr: EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.qr).collect(), domain.d1).interpolate(),
            qo: EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.qo).collect(), domain.d1).interpolate(),
            qm: EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.qm).collect(), domain.d1).interpolate(),
            qc: EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.qc).collect(), domain.d1).interpolate(),
            
            rc: array_init(|i| EvaluationDomains::evals_from_coeffs(gates.iter().map(|gate| gate.rc[i]).collect(), domain.d1).interpolate()),
            p2: EvaluationDomains::evals_from_coeffs(pm.coeffs, domain.d2).evals,
            pbox,
            
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
        if witness.len() != 3*self.domain.d1.size() {return false}
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

    // poseidon witness poly multiplication f*(1-W) + f^17*W
    pub fn posmul(&self, polys: &[&DensePolynomial<F>]) -> DensePolynomial<F>
    {
        let mut evals = polys.iter().map
        (
            |poly|
            {
                let mut evals = poly.evaluate_over_domain_by_ref(self.domain.dp);
                evals.evals.iter_mut().for_each(|e| *e = e.pow([oracle::poseidon::SPONGE_BOX as u64]));
                evals
            }
        ).fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.dp), |x, y| &x + &y);
        evals.evals.iter_mut().zip(self.pbox.iter()).for_each(|(e, p)| *e *= p);

        let mut ret = evals.interpolate();

        let evals = polys.iter().map
        (
            |poly|
            {
                let mut evals = poly.evaluate_over_domain_by_ref(self.domain.d2);
                evals.evals.iter_mut().zip(self.p2.iter()).for_each(|(e, p)| *e *= p);
                evals
            }
        ).fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.dp), |x, y| &x + &y);

        ret += &evals.interpolate();
        ret
    }
}
