/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use ff_fft::{EvaluationDomain, DensePolynomial};
pub use super::gate::{CircuitGate, SPONGE_WIDTH};
pub use super::domains::EvaluationDomains;
use array_init::array_init;
use oracle::utils::Utils;
use rand_core::OsRng;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField>
{
    pub public: usize,                      // number of public inputs
    pub domain: EvaluationDomains<F>,       // evaluation domains
    pub gates:  Vec<CircuitGate<F>>,        // circuit gates

    // polynomials over the monomial base    
    pub sigmam: [DensePolynomial<F>; 3],    // permutation polynomial array

    // generic constraint selector polynomials
    pub ql:     DensePolynomial<F>,         // left input wire polynomial
    pub qr:     DensePolynomial<F>,         // right input wire polynomial
    pub qo:     DensePolynomial<F>,         // output wire polynomial
    pub qm:     DensePolynomial<F>,         // multiplication polynomial
    pub qc:     DensePolynomial<F>,         // constant wire polynomial

    // poseidon selector polynomials
    pub rcm:    [DensePolynomial<F>; SPONGE_WIDTH], // round constant polynomials
    pub fpm:    DensePolynomial<F>,         // full/partial round indicator polynomial
    pub pfm:    DensePolynomial<F>,         // partial/full round indicator polynomial
    pub psm:    DensePolynomial<F>,         // poseidon constraint selector polynomial
    
    // permutation polynomials over Lagrange base
    pub sigmal: [Vec<F>; 3],                // permutation polynomial array
    pub sid:    Vec<F>,                     // SID polynomial

    // poseidon selector polynomials over Lagrange bases
    pub fpl:    Vec<F>,                     // full/partial round indicator evaluations w over domain.dp
    pub pfl:    Vec<F>,                     // partial/full round indicator 1-w evaluations over domain.d2
    pub psl:    Vec<F>,                     // poseidon selector over domain.d2

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
        let fpm = DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.fp * &gate.ps).collect(), domain.d1).interpolate();
        let pfm = DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| (F::one()-&gate.fp)*&gate.ps).collect(), domain.d1).interpolate();
        let psm = DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.ps).collect(), domain.d1).interpolate();

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmam: array_init(|i| DensePolynomial::evals_from_coeffs(sigmal[i].clone(), domain.d1).interpolate()),
            sigmal,
            ql: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.ql).collect(), domain.d1).interpolate(),
            qr: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qr).collect(), domain.d1).interpolate(),
            qo: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qo).collect(), domain.d1).interpolate(),
            qm: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qm).collect(), domain.d1).interpolate(),
            qc: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qc).collect(), domain.d1).interpolate(),
            
            rcm: array_init(|i| DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.rc[i]).collect(), domain.d1).interpolate()),
            psl: psm.evaluate_over_domain_by_ref(domain.d2).evals,
            fpl: fpm.evaluate_over_domain_by_ref(domain.dp).evals,
            pfl: pfm.evaluate_over_domain_by_ref(domain.d2).evals,
            psm,
            fpm,
            pfm,
            
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

    // poseidon quotient poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_quot(&self, polys: &[&DensePolynomial<F>], i: usize, f: &DensePolynomial<F>) -> DensePolynomial<F>
    {
        let mut evals = polys.iter().map
        (
            |poly|
            {
                let mut evals = poly.evaluate_over_domain_by_ref(self.domain.dp);
                evals.evals.iter_mut().for_each(|e| *e = oracle::poseidon::sbox(*e));
                evals
            }
        ).fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.dp), |x, y| &x + &y);
        evals.evals.iter_mut().zip(self.fpl.iter()).for_each(|(e, p)| *e *= p);

        let mut ret = evals.interpolate();

        let mut evals = polys.iter().map
        (
            |poly|
            {
                let mut evals = poly.evaluate_over_domain_by_ref(self.domain.d2);
                evals.evals.iter_mut().zip(self.pfl.iter()).for_each(|(e, p)| *e *= p);
                evals
            }
        ).fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d2), |x, y| &x + &y);

        evals -=
        &{
            let mut evals = self.shift(f).evaluate_over_domain_by_ref(self.domain.d2);
            evals.evals.iter_mut().zip(self.psl.iter()).for_each(|(e, p)| *e *= p);
            evals
        };

        ret += &(&evals.interpolate() + &self.rcm[i]);
        ret
    }

    // poseidon linearization poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_lnrz(&self, evals: &[F], i: usize, f: F) -> DensePolynomial<F>
    {
        &(&(&evals.iter().map
        (
            |eval| {self.fpm.scale(oracle::poseidon::sbox(*eval))}
        ).fold(DensePolynomial::<F>::zero(), |x, y| &x + &y)
        +
        &evals.iter().map
        (
            |eval| {self.pfm.scale(*eval)}
        ).fold(DensePolynomial::<F>::zero(), |x, y| &x + &y))
        + &self.psm.scale(f)) + &self.rcm[i]
    }

    // utility function for eshifting poly along domain coordinate
    pub fn shift(&self, poly: &DensePolynomial<F>) -> DensePolynomial<F>
    {
        DensePolynomial::from_coefficients_vec(poly.coeffs.iter().zip(self.sid.iter()).
            map(|(p, w)| *p * w).collect::<Vec<_>>())
    }
}
