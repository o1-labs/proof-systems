/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use blake2::{Blake2b, Digest};
use algebra::{FftField, SquareRootField};
use oracle::poseidon::ArithmeticSpongeParams;
use ff_fft::{EvaluationDomain, DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
use crate::nolookup::constraints::ConstraintSystem as CS;
use crate::gate::{CircuitGate, GateType};
use crate::wires::{Wire, COLUMNS, WIRES};
use crate::domains::EvaluationDomains;
use oracle::utils::EvalUtils;
use array_init::array_init;
use crate::polynomial::*;

pub struct ConstraintSystem<F: FftField>
{
    pub cs: CS<F>,                      // plonk constraint system

    // POLYNOMIALS OVER THE MONOMIAL BASE

    pub lkpm:   DP<F>,                  // lookup constraint selector polynomial
    pub tablem: DP<F>,                  // lookup table polynomial

    // POLYNOMIALS OVER LAGRANGE BASE

    pub lkpl4:  E<F, D<F>>,             // lookup constraint selector polynomial over domain.d4
    pub lkpl8:  E<F, D<F>>,             // lookup constraint selector polynomial over domain.d8
    pub table8w:E<F, D<F>>,             // shifted lookup table polynomial over domain.d8
    pub table8: E<F, D<F>>,             // lookup table polynomial over domain.d8
    pub table1: E<F, D<F>>,             // lookup table polynomial over domain.d1

    // constant polynomials
    pub l14:    E<F, D<F>>,             // 1-st Lagrange evaluated over domain.d4
    pub l18:    E<F, D<F>>,             // 1-st Lagrange evaluated over domain.d8
}

pub fn zk_w1<F:FftField>(domain : D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 1])
}

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    pub fn create
    (
        mut gates: Vec<CircuitGate<F>>,
        mut tbl: Vec<F>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = EvaluationDomains::<F>::create(if gates.len() > tbl.len() {gates.len()} else {tbl.len()})?;
        let mut sid = domain.d1.elements().map(|elm| {elm}).collect::<Vec<_>>();

        let n = domain.d1.size();
        let mut padding = (gates.len()..n).map(|i| CircuitGate::<F>::zero(i, array_init(|j| Wire{col:WIRES[j], row:i}))).collect();
        gates.append(&mut padding);

        // lookup constraint polynomials
        let lkpm = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.lookup()).collect(), domain.d1).interpolate();
        let lkpl8 = lkpm.evaluate_over_domain_by_ref(domain.d8);

        // lookup table polynonials
        tbl.sort_unstable();
        let mut table = vec![F::zero(); n - tbl.len()];
        table.append(&mut tbl);
        let table1 = E::<F, D<F>>::from_vec_and_domain(table, domain.d1); 
        let tablem = table1.clone().interpolate();
        let table8 = tablem.evaluate_over_domain_by_ref(domain.d8);

        // constant polynomials
        let l18 = DP::from_coefficients_slice(&[F::zero(), F::one()]).evaluate_over_domain_by_ref(domain.d8);

        Some(ConstraintSystem
        {
            cs: CS::<F>::create(gates, fr_sponge_params, public)?,

            // lookup constraint polynomials
            lkpl4: E::<F, D<F>>::from_vec_and_domain((0..domain.d4.size).map(|j| lkpl8.evals[2*j as usize]).collect(), domain.d4),
            lkpl8,
            lkpm,

            // lookup table polynonial
            table1,
            table8w: table8.shift(8),
            table8,
            tablem,

            // constant polynomials
            l14: E::<F, D<F>>::from_vec_and_domain((0..domain.d4.size).map(|j| l18.evals[2*j as usize]).collect(), domain.d4),
            l18,
        })
    }
    // evaluate lookup polynomials over domains
    pub fn evaluate
    (
        &self,
        polys: &LookupPolys<F>,
    ) -> LookupShifts<F>
    {
        let l = polys.l.evaluate_over_domain_by_ref(self.cs.domain.d8);
        let lw = polys.lw.evaluate_over_domain_by_ref(self.cs.domain.d8);
        let h1 = polys.h1.evaluate_over_domain_by_ref(self.cs.domain.d8);
        let h2 = polys.h2.evaluate_over_domain_by_ref(self.cs.domain.d8);

        LookupShifts
        {
            next: LookupEvals
            {
                l: l.shift(8),
                lw: DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap()), // dummy
                h1: h1.shift(8),
                h2: h2.shift(8)
            },
            this: LookupEvals
            {
                l,
                lw,
                h1,
                h2
            }
        }
    }
}
