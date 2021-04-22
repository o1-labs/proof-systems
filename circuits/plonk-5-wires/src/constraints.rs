/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use oracle::poseidon::ArithmeticSpongeParams;
use ff_fft::{EvaluationDomain, DensePolynomial as DP, Evaluations as E, Radix2EvaluationDomain as D};
pub use super::polynomial::{WitnessOverDomains, WitnessShifts, WitnessEvals};
pub use super::gate::{CircuitGate, GateType};
pub use super::wires::{Wire, COLUMNS, WIRES};
pub use super::domains::EvaluationDomains;
use blake2::{Blake2b, Digest};
use oracle::utils::EvalUtils;
use array_init::array_init;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField>
{
    pub public: usize,                  // number of public inputs
    pub domain: EvaluationDomains<F>,   // evaluation domains
    pub gates:  Vec<CircuitGate<F, GateType>>,    // circuit gates

    // POLYNOMIALS OVER THE MONOMIAL BASIS

    pub sigmam: [DP<F>; COLUMNS],       // permutation polynomial array
    pub zkpm:   DP<F>,                  // zero-knowledge polynomial

    // generic constraint selector polynomials
    pub qwm:    [DP<F>; COLUMNS],       // linear wire constraint polynomial
    pub qmm:    DP<F>,                  // multiplication polynomial
    pub qc:     DP<F>,                  // constant wire polynomial

    // poseidon selector polynomials
    pub rcm:    [DP<F>; COLUMNS],       // round constant polynomials
    pub psm:    DP<F>,                  // poseidon constraint selector polynomial

    pub packm:  DP<F>,                  // packing constraint selector polynomial

    // ECC arithmetic selector polynomials
    pub addm:   DP<F>,                  // EC point addition constraint selector polynomial
    pub doublem:DP<F>,                  // EC point doubling constraint selector polynomial
    pub mul1m:  DP<F>,                  // mul1m constraint selector polynomial
    pub mul2m:  DP<F>,                  // mul2m constraint selector polynomial
    pub emulm:  DP<F>,                  // emul1m constraint selector polynomial

    // POLYNOMIALS OVER LAGRANGE BASIS

    // generic constraint selector polynomials
    pub qwl:    [E<F, D<F>>; COLUMNS],  // left input wire polynomial over domain.d4
    pub qml:    E<F, D<F>>,             // multiplication evaluations over domain.d4

    // permutation polynomials
    pub sigmal1:[Vec<F>; COLUMNS],      // permutation polynomial array evaluations over domain d1
    pub sigmal8:[E<F, D<F>>; COLUMNS],  // permutation polynomial array evaluations over domain d8
    pub sid:    Vec<F>,                 // SID polynomial

    // poseidon selector polynomials
    pub ps4:    E<F, D<F>>,             // poseidon selector over domain.d4
    pub ps8:    E<F, D<F>>,             // poseidon selector over domain.d8

    pub packl:  E<F, D<F>>,             // packing constraint selector polynomial over domain.d4

    // ECC arithmetic selector polynomials
    pub addl:   E<F, D<F>>,             // EC point addition selector evaluations w over domain.d4
    pub doublel:E<F, D<F>>,             // EC point doubling selector evaluations w over domain.d8
    pub mul1l:  E<F, D<F>>,             // scalar multiplication selector evaluations over domain.d4
    pub mul2l:  E<F, D<F>>,             // scalar multiplication selector evaluations over domain.d8
    pub emull:  E<F, D<F>>,             // endoscalar multiplication selector evaluations over domain.d4

    // constant polynomials
    pub l1:     E<F, D<F>>,             // 1-st Lagrange evaluated over domain.d8
    pub l04:    E<F, D<F>>,             // 0-th Lagrange evaluated over domain.d4
    pub l08:    E<F, D<F>>,             // 0-th Lagrange evaluated over domain.d8
    pub zero4:  E<F, D<F>>,             // zero evaluated over domain.d8
    pub zero8:  E<F, D<F>>,             // zero evaluated over domain.d8
    pub zkpl:   E<F, D<F>>,             // zero-knowledge polynomial over domain.d8

    pub shift: [F; COLUMNS],            // wire coordinate shifts
    pub endo:   F,                      // coefficient for the group endomorphism

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<F>,
}

pub fn zk_w<F:FftField>(domain : D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 3])
}

pub fn zk_polynomial<F:FftField>(domain : D<F>) -> DP<F> {
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w3 = zk_w(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    DP::from_coefficients_slice(&
    [
        -w1*&w2*&w3,
        (w1*&w2) + &(w1*&w3) + &(w3*&w2),
        -w1 - &w2 - &w3,
        F::one()
    ])
}

impl<F: FftField + SquareRootField> ConstraintSystem<F>
{
    pub fn create
    (
        mut gates: Vec<CircuitGate<F, GateType>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = EvaluationDomains::<F>::create(gates.len())?;
        let mut sid = domain.d1.elements().map(|elm| {elm}).collect::<Vec<_>>();

        // sample the coordinate shifts
        let shift = Self::sample_shifts(&domain.d1, COLUMNS - 1);
        let shift = [F::one(), shift[0], shift[1], shift[2], shift[3]];

        let n = domain.d1.size();
        let mut padding = (gates.len()..n).map(|i| CircuitGate::<F, GateType>::zero(i, array_init(|j| Wire{col:WIRES[j], row:i}))).collect();
        gates.append(&mut padding);

        let s: [std::vec::Vec<F>; COLUMNS] = array_init(|i| domain.d1.elements().map(|elm| {shift[i] * &elm}).collect());
        let mut sigmal1 = s.clone();

        // compute permutation polynomials
        gates.iter().enumerate().for_each
        (
            |(i, _)| (0..COLUMNS).for_each(|j| {let wire = gates[i].wires[j]; sigmal1[j][i] = s[wire.col][wire.row]})
        );
        let sigmam: [DP<F>; COLUMNS] = array_init
            (|i| E::<F, D<F>>::from_vec_and_domain(sigmal1[i].clone(), domain.d1).interpolate());

        let mut s = sid[0..2].to_vec();
        sid.append(&mut s);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);

        // compute generic constraint polynomials
        let qwm: [DP<F>; COLUMNS] = array_init(|i| E::<F, D<F>>::from_vec_and_domain(gates.iter().
            map(|gate| if gate.typ == GateType::Generic {gate.c[WIRES[i]]} else {F::zero()}).collect(), domain.d1).interpolate());
        let qmm = E::<F, D<F>>::from_vec_and_domain(gates.iter().
            map(|gate| if gate.typ == GateType::Generic {gate.c[COLUMNS]} else {F::zero()}).collect(), domain.d1).interpolate();

        // compute poseidon constraint polynomials
        let psm = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.ps()).collect(), domain.d1).interpolate();

        // compute packing constraint polynomials
        let packm = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.pack()).collect(), domain.d1).interpolate();

        // compute ECC arithmetic constraint polynomials
        let addm = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.add()).collect(), domain.d1).interpolate();
        let doublem = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.double()).collect(), domain.d1).interpolate();
        let mul1m = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.vbmul1()).collect(), domain.d1).interpolate();
        let mul2m = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.vbmul2()).collect(), domain.d1).interpolate();
        let emulm = E::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.endomul()).collect(), domain.d1).interpolate();

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmal1,
            sigmal8: array_init(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8)),
            sigmam,

            // generic constraint polynomials
            qwl: array_init(|i| qwm[i].evaluate_over_domain_by_ref(domain.d4)),
            qml: qmm.evaluate_over_domain_by_ref(domain.d4),
            qwm,
            qmm,
            qc: E::<F, D<F>>::from_vec_and_domain(gates.iter().
                map(|gate| if gate.typ == GateType::Generic {gate.c[COLUMNS+1]} else {F::zero()}).collect(), domain.d1).interpolate(),

            // poseidon constraint polynomials
            rcm: array_init(|i| E::<F, D<F>>::from_vec_and_domain(gates.iter().
                map(|gate| if gate.typ == GateType::Poseidon {gate.rc()[i]} else {F::zero()}).collect(), domain.d1).interpolate()),
            ps4: psm.evaluate_over_domain_by_ref(domain.d4),
            ps8: psm.evaluate_over_domain_by_ref(domain.d8),
            psm,

            // packing constraint polynomials
            packl: packm.evaluate_over_domain_by_ref(domain.d4),
            packm,

            // ECC arithmetic constraint polynomials
            addl: addm.evaluate_over_domain_by_ref(domain.d4),
            addm,
            doublel: doublem.evaluate_over_domain_by_ref(domain.d8),
            doublem,
            mul1l: mul1m.evaluate_over_domain_by_ref(domain.d4),
            mul2l: mul2m.evaluate_over_domain_by_ref(domain.d8),
            mul1m,
            mul2m,
            emull: emulm.evaluate_over_domain_by_ref(domain.d4),
            emulm,

            // constant polynomials
            l1: DP::from_coefficients_slice(&[F::zero(), F::one()]).evaluate_over_domain_by_ref(domain.d8),
            l04: E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size as usize], domain.d4),
            l08: E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size as usize], domain.d8),
            zero4: E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d4.size as usize], domain.d4),
            zero8: E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d8.size as usize], domain.d8),
            zkpl: zkpm.evaluate_over_domain_by_ref(domain.d8),
            zkpm,

            gates,
            shift,
            endo: F::zero(),
            fr_sponge_params,
        })
    }

    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &[Vec<F>; COLUMNS]
    ) -> bool
    {
        let p = vec![F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
        (0..self.gates.len()).all
        (
            |j|
                // verify permutation consistency
                (0..COLUMNS).all(|i|
                {
                    let wire = self.gates[j].wires[i];
                    witness[i][j] == witness[wire.col][wire.row]
                })
                &&
                // verify witness against constraints
                if j < self.public {self.gates[j].c == p} else {self.gates[j].verify(witness, &self)}
        )
    }

    // sample coordinate shifts deterministically
    pub fn sample_shift(domain: &D<F>, i: &mut u32) -> F
    {
        let mut h = Blake2b::new();
        h.input(&{*i += 1; *i}.to_be_bytes());
        let mut r = F::from_random_bytes(&h.result()[..31]).unwrap();
        while r.legendre().is_qnr() == false || domain.evaluate_vanishing_polynomial(r).is_zero()
        {
            let mut h = Blake2b::new();
            h.input(&{*i += 1; *i}.to_be_bytes());
            r = F::from_random_bytes(&h.result()[..31]).unwrap();
        }
        r
    }

    pub fn sample_shifts(domain: &D<F>, len: usize) -> Vec<F>
    {
        let mut i: u32 = 7;
        let mut shifts = Vec::with_capacity(len);
        while shifts.len() < len
        {
            let mut o = Self::sample_shift(&domain, &mut i);
            while shifts.iter().filter(|&r| o == *r).count() > 0 {o = Self::sample_shift(&domain, &mut i)}
            shifts.push(o)
        }
        shifts
    }

    // evaluate witness polynomials over domains
    pub fn evaluate
    (
        &self,
        w: &[DP<F>; COLUMNS],
        z: &DP<F>,
    ) -> WitnessOverDomains<F>
    {
        // compute shifted witness polynomials
        let w8: [E<F, D<F>>; COLUMNS] = array_init(|i| w[i].evaluate_over_domain_by_ref(self.domain.d8));
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        let w4: [E<F, D<F>>; COLUMNS] = array_init(|i| E::<F, D<F>>::from_vec_and_domain((0..self.domain.d4.size).
            map(|j| w8[i].evals[2*j as usize]).collect(), self.domain.d4));
        let z4 = DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap());

        WitnessOverDomains
        {
            d4: WitnessShifts
            {
                next: WitnessEvals
                {
                    w: array_init(|i| w4[i].shift(4)),
                    z: z4.clone() // dummy evaluation
                },
                this: WitnessEvals
                {
                    w: w4,
                    z: z4, // dummy evaluation
                },
            },
            d8: WitnessShifts
            {
                next: WitnessEvals
                {
                    w: array_init(|i| w8[i].shift(8)),
                    z: z8.shift(8),
                },
                this: WitnessEvals
                {
                    w: w8,
                    z: z8
                },
            },
        }
    }
}
