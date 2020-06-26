/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use oracle::{utils::Utils, poseidon::sbox};
use ff_fft::{EvaluationDomain, DensePolynomial};
pub use super::gate::{CircuitGate, GateType, SPONGE_WIDTH};
pub use super::domains::EvaluationDomains;
use array_init::array_init;
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
    pub ps2:    Vec<F>,                     // poseidon selector over domain.d2
    pub psp:    Vec<F>,                     // poseidon selector over domain.dp

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
        let mut padding = (gates.len()..n).map(|i| CircuitGate::<F>::zero((i,i), (n+i,n+i), (2*n+i,2*n+i))).collect();
        gates.append(&mut padding);

        let s =
        [
            sid.clone(),
            domain.d1.elements().map(|elm| {r * &elm}).collect(),
            domain.d1.elements().map(|elm| {o * &elm}).collect(),
        ];
        let mut sigmal = s.clone();

        // compute permutation polynomials
        gates.iter().filter(|&g| g.typ != GateType::Zero).for_each
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
        let psm = DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.ps()).collect(), domain.d1).interpolate();
        let fpm = DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.fp()).collect(), domain.d1).interpolate();
        let pfm = &psm - &fpm;

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmam: array_init(|i| DensePolynomial::evals_from_coeffs(sigmal[i].clone(), domain.d1).interpolate()),
            sigmal,
            ql: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.ql()).collect(), domain.d1).interpolate(),
            qr: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qr()).collect(), domain.d1).interpolate(),
            qo: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qo()).collect(), domain.d1).interpolate(),
            qm: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qm()).collect(), domain.d1).interpolate(),
            qc: DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.qc()).collect(), domain.d1).interpolate(),
            
            rcm: array_init(|i| DensePolynomial::evals_from_coeffs(gates.iter().map(|gate| gate.rc()[i]).collect(), domain.d1).interpolate()),
            ps2: psm.evaluate_over_domain_by_ref(domain.d2).evals,
            psp: psm.evaluate_over_domain_by_ref(domain.dp).evals,
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
        if witness.len() != 3*self.domain.d1.size() {return false}
        for i in self.public..self.gates.len()
        {
            if
            // verify permutation consistency
            witness[self.gates[i].l.1] != witness[self.gates[i].l.0] ||
            witness[self.gates[i].r.1] != witness[self.gates[i].r.0] ||
            witness[self.gates[i].o.1] != witness[self.gates[i].o.0] ||
            
            // verify witness against constraints
            !self.gates[i].verify(witness, if i+1==self.gates.len() {&self.gates[i]} else {&self.gates[i+1]})
            {
                return false
            }
        }
        true
    }

    // poseidon quotient poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_quot(&self, polys: &[&DensePolynomial<F>; 3], alpha: &[F; 3]) -> DensePolynomial<F>
    {
        let mut evals = polys.iter().map(|poly| poly.evaluate_over_domain_by_ref(self.domain.dp)).collect::<Vec<_>>();

        evals[0].evals.iter_mut().zip(self.psp.iter()).for_each(|(l, p)| *l = sbox(*l) * p);
        evals[1].evals.iter_mut().zip(self.fpl.iter()).for_each(|(r, p)| *r = sbox(*r) * p);
        evals[2].evals.iter_mut().zip(self.fpl.iter()).for_each(|(o, p)| *o = sbox(*o) * p);

        let mut rows = [&evals[0] + &evals[2], &evals[0] + &evals[1], &evals[1] + &evals[2]];

        let mut ret = rows.iter_mut().zip(alpha.iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.dp), |x, y| &x + &y).
            interpolate();

        let mut shifts = polys.iter().map(|poly| self.shift(poly).evaluate_over_domain_by_ref(self.domain.d2)).collect::<Vec<_>>();
        shifts.iter_mut().for_each(|s| s.evals.iter_mut().zip(self.ps2.iter()).for_each(|(s, p)| *s *= p));

        let mut r = polys[1].evaluate_over_domain_by_ref(self.domain.d2);
        r.evals.iter_mut().zip(self.pfl.iter()).for_each(|(r, p)| *r *= p);
        let mut o = polys[2].evaluate_over_domain_by_ref(self.domain.d2);
        o.evals.iter_mut().zip(self.pfl.iter()).for_each(|(o, p)| *o *= p);

        let mut rows = [&o - &shifts[0], &r - &shifts[1], &(&r + &o) - &shifts[2]];

        ret += &rows.iter_mut().zip(alpha.iter()).
            map(|(e, a)| {e.evals.iter_mut().for_each(|e| *e *= a); e}).
            fold(DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(self.domain.d2), |x, y| &x + &y).
            interpolate();

        self.rcm.iter().zip(alpha.iter()).map(|(r, a)| r.scale(*a)).fold(ret, |x, y| &x + &y)
    }

    // poseidon linearization poly contribution computation f*(1-W) + f^5*W + c(x) - f(wx)
    pub fn psdn_lnrz(&self, evals: &[F; 3], shifts: &[F; 3], alpha: &[F; 3]) -> DensePolynomial<F>
    {
        let l = sbox(evals[0]);
        let r = sbox(evals[1]);
        let o = sbox(evals[2]);

        let ret =
            &(&self.fpm.scale((o * &alpha[0]) + &(r * &alpha[1]) + &((r + &o) * &alpha[2])) +
            &self.pfm.scale((evals[2] * &alpha[0]) + &(evals[1] * &alpha[1]) + &((evals[1] + &evals[2]) * &alpha[2]))) +
            &self.psm.scale(((l - &shifts[0]) * &alpha[0]) + &((l - &shifts[1]) * &alpha[1]) - &(shifts[2] * &alpha[2]));
        
        self.rcm.iter().zip(alpha.iter()).map(|(r, a)| r.scale(*a)).fold(ret, |x, y| &x + &y)

    }

    // utility function for shifting poly along domain coordinate
    pub fn shift(&self, poly: &DensePolynomial<F>) -> DensePolynomial<F>
    {
        DensePolynomial::from_coefficients_vec(poly.coeffs.iter().zip(self.sid.iter()).
            map(|(p, w)| *p * w).collect::<Vec<_>>())
    }
}
