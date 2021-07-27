/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use algebra::{FftField, SquareRootField};
use oracle::poseidon::{SpongeConstants, PlonkSpongeConstants, ArithmeticSpongeParams};
use ff_fft::{EvaluationDomain, DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
pub use super::polynomial::{WitnessOverDomains, WitnessShifts, WitnessEvals};
pub use super::gate::{CircuitGate, GateType};
pub use super::domains::EvaluationDomains;
pub use super::wires::GateWires;
use blake2::{Blake2b, Digest};
use oracle::utils::EvalUtils;
use array_init::array_init;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField>
{
    pub public: usize,                      // number of public inputs
    pub domain: EvaluationDomains<F>,       // evaluation domains
    pub gates:  Vec<CircuitGate<F>>,        // circuit gates

    // POLYNOMIALS OVER THE MONOMIAL BASE

    pub sigmam: [DensePolynomial<F>; 3],    // permutation polynomial array
    pub zkpm:   DensePolynomial<F>,         // zero-knowledge polynomial

    // generic constraint selector polynomials
    pub qlm:    DensePolynomial<F>,         // left input wire polynomial
    pub qrm:    DensePolynomial<F>,         // right input wire polynomial
    pub qom:    DensePolynomial<F>,         // output wire polynomial
    pub qmm:    DensePolynomial<F>,         // multiplication polynomial
    pub qc:     DensePolynomial<F>,         // constant wire polynomial

    // poseidon selector polynomials
    pub rcm:    [DensePolynomial<F>; PlonkSpongeConstants::SPONGE_WIDTH], // round constant polynomials
    pub psm:    DensePolynomial<F>,         // poseidon constraint selector polynomial

    // EC point addition constraint polynomials
    pub addm:   DensePolynomial<F>,         // EC point addition constraint selector polynomial

    // variable base scalar multiplication constraint polynomials
    pub mul1m:  DensePolynomial<F>,         // mul1m constraint selector polynomial
    pub mul2m:  DensePolynomial<F>,         // mul1m constraint selector polynomial
    pub emul1m: DensePolynomial<F>,         // emul1m constraint selector polynomial
    pub emul2m: DensePolynomial<F>,         // emul2m constraint selector polynomial
    pub emul3m: DensePolynomial<F>,         // emul3m constraint selector polynomial

    // POLYNOMIALS OVER LAGRANGE BASE

    // generic constraint selector polynomials
    pub qll:    Evaluations<F, D<F>>,       // left input wire polynomial over domain.d4
    pub qrl:    Evaluations<F, D<F>>,       // right input wire polynomial over domain.d4
    pub qol:    Evaluations<F, D<F>>,       // output wire polynomial over domain.d4
    pub qml:    Evaluations<F, D<F>>,       // multiplication evaluations over domain.d4

    // permutation polynomials
    pub sigmal1:[Vec<F>; 3],                // permutation polynomial array evaluations over domain d1
    pub sigmal4:[Evaluations<F, D<F>>; 3],  // permutation polynomial array evaluations over domain d8
    pub sid:    Vec<F>,                     // SID polynomial

    // poseidon selector polynomials
    pub ps4:    Evaluations<F, D<F>>,       // poseidon selector over domain.d4
    pub ps8:    Evaluations<F, D<F>>,       // poseidon selector over domain.d8

    // ECC arithmetic selector polynomials
    pub addl4:  Evaluations<F, D<F>>,       // EC point addition selector evaluations w over domain.d4
    pub mul1l:  Evaluations<F, D<F>>,       // scalar multiplication selector evaluations over domain.d4
    pub mul2l:  Evaluations<F, D<F>>,       // scalar multiplication selector evaluations over domain.d8
    pub emul1l: Evaluations<F, D<F>>,       // endoscalar multiplication selector evaluations over domain.d4
    pub emul2l: Evaluations<F, D<F>>,       // endoscalar multiplication selector evaluations over domain.d4
    pub emul3l: Evaluations<F, D<F>>,       // endoscalar multiplication selector evaluations over domain.d8

    pub l04:    Evaluations<F, D<F>>,       // 0-th Lagrange evaluated over domain.d4
    pub l08:    Evaluations<F, D<F>>,       // 0-th Lagrange evaluated over domain.d8
    pub l1:     Evaluations<F, D<F>>,       // 1-st Lagrange evaluated over domain.d8
    pub zkpl:   Evaluations<F, D<F>>,       // zero-knowledge polynomial over domain.d8

    pub r:      F,                          // coordinate shift for right wires
    pub o:      F,                          // coordinate shift for output wires
    pub endo:   F,                          // coefficient for the group endomorphism

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<F>,
}

pub fn zk_w<F:FftField>(domain : D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 3])
}

pub fn zk_polynomial<F:FftField>(domain : D<F>) -> DensePolynomial<F> {
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w3 = zk_w(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    DensePolynomial::from_coefficients_slice(&
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
        mut gates: Vec<CircuitGate<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self>
    {
        let domain = EvaluationDomains::<F>::create(gates.len())?;
        let mut sid = domain.d1.elements().map(|elm| {elm}).collect::<Vec<_>>();

        // sample the coordinate shifts
        let (r, o) = Self::sample_shifts(&domain.d1);

        let n = domain.d1.size();
        let mut padding = (gates.len()..n).map(|i| CircuitGate::<F>::zero(GateWires::wires((i,i), (n+i,n+i), (2*n+i,2*n+i)))).collect();
        gates.append(&mut padding);

        let s =
        [
            sid.clone(),
            domain.d1.elements().map(|elm| {r * &elm}).collect(),
            domain.d1.elements().map(|elm| {o * &elm}).collect(),
        ];
        let mut sigmal1 = s.clone();

        // compute permutation polynomials
        gates.iter().for_each
        (
            |gate|
            {
                sigmal1[0][gate.wires.l.0] = s[gate.wires.l.1 / n][gate.wires.l.1 % n];
                sigmal1[1][gate.wires.r.0-n] = s[gate.wires.r.1 / n][gate.wires.r.1 % n];
                sigmal1[2][gate.wires.o.0-2*n] = s[gate.wires.o.1 / n][gate.wires.o.1 % n];
            }
        );
        let sigmam: [DensePolynomial<F>; 3] = array_init
            (|i| Evaluations::<F, D<F>>::from_vec_and_domain(sigmal1[i].clone(), domain.d1).interpolate());

        let mut s = sid[0..2].to_vec();
        sid.append(&mut s);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);

        // compute generic constraint polynomials
        let qlm = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.ql()).collect(), domain.d1).interpolate();
        let qrm = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.qr()).collect(), domain.d1).interpolate();
        let qom = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.qo()).collect(), domain.d1).interpolate();
        let qmm = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.qm()).collect(), domain.d1).interpolate();

        // compute poseidon constraint polynomials
        let psm = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.ps()).collect(), domain.d1).interpolate();

        // compute ECC arithmetic constraint polynomials
        let addm = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.add1()).collect(), domain.d1).interpolate();
        let mul1m = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.vbmul1()).collect(), domain.d1).interpolate();
        let mul2m = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.vbmul2()).collect(), domain.d1).interpolate();
        let emul1m = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.endomul1()).collect(), domain.d1).interpolate();
        let emul2m = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.endomul2()).collect(), domain.d1).interpolate();
        let emul3m = Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.endomul3()).collect(), domain.d1).interpolate();

        Some(ConstraintSystem
        {
            domain,
            public,
            sid,
            sigmal1,
            sigmal4: array_init(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8)),
            sigmam,

            // generic constraint polynomials
            qll: qlm.evaluate_over_domain_by_ref(domain.d4),
            qrl: qrm.evaluate_over_domain_by_ref(domain.d4),
            qol: qom.evaluate_over_domain_by_ref(domain.d4),
            qml: qmm.evaluate_over_domain_by_ref(domain.d4),
            qlm,
            qrm,
            qom,
            qmm,
            qc: Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.qc()).collect(), domain.d1).interpolate(),

            // poseidon constraint polynomials
            rcm: array_init(|i| Evaluations::<F, D<F>>::from_vec_and_domain(gates.iter().map(|gate| gate.rc()[i]).collect(), domain.d1).interpolate()),
            ps4: psm.evaluate_over_domain_by_ref(domain.d4),
            ps8: psm.evaluate_over_domain_by_ref(domain.d8),
            psm,

            // ECC arithmetic constraint polynomials
            addl4: addm.evaluate_over_domain_by_ref(domain.d4),
            addm,
            mul1l: mul1m.evaluate_over_domain_by_ref(domain.d4),
            mul2l: mul2m.evaluate_over_domain_by_ref(domain.d8),
            mul1m,
            mul2m,
            emul1l: emul1m.evaluate_over_domain_by_ref(domain.d4),
            emul2l: emul2m.evaluate_over_domain_by_ref(domain.d4),
            emul3l: emul3m.evaluate_over_domain_by_ref(domain.d8),
            emul1m,
            emul2m,
            emul3m,

            l04: DensePolynomial::from_coefficients_slice(&[F::one()]).evaluate_over_domain_by_ref(domain.d4),
            l08: DensePolynomial::from_coefficients_slice(&[F::one()]).evaluate_over_domain_by_ref(domain.d8),
            l1: DensePolynomial::from_coefficients_slice(&[F::zero(), F::one()]).evaluate_over_domain_by_ref(domain.d8),
            zkpl: zkpm.evaluate_over_domain_by_ref(domain.d8),
            zkpm,

            gates,
            r,
            o,
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
        witness: &Vec<F>
    ) -> bool
    {
        if witness.len() != 3*self.domain.d1.size() {return false}
        for i in self.public..self.gates.len()
        {
            if
            // verify permutation consistency
            witness[self.gates[i].wires.l.1] != witness[self.gates[i].wires.l.0] ||
            witness[self.gates[i].wires.r.1] != witness[self.gates[i].wires.r.0] ||
            witness[self.gates[i].wires.o.1] != witness[self.gates[i].wires.o.0] ||

            // verify witness against constraints
            !self.gates[i].verify(if i+1==self.gates.len() {&self.gates[i]}
                                                      else {&self.gates[i+1]}, witness, &self)
            {
                return false
            }
        }
        true
    }

    // sample coordinate shifts deterministically
    fn sample_shift(domain: &D<F>, i: &mut u32) -> F
    {
        let mut h = Blake2b::new();
        h.update(
            &{
                *i += 1;
                *i
            }
            .to_be_bytes(),
        );
        let mut r = F::from_random_bytes(&h.finalize()[..31]).unwrap();
        while r.legendre().is_qnr() == false || domain.evaluate_vanishing_polynomial(r).is_zero() {
            let mut h = Blake2b::new();
            h.update(
                &{
                    *i += 1;
                    *i
                }
                .to_be_bytes(),
            );
            r = F::from_random_bytes(&h.finalize()[..31]).unwrap();
        }
        r
    }

    pub fn sample_shifts(domain: &D<F>) -> (F, F) {
        let mut i: u32 = 7;
        let r = Self::sample_shift(&domain, &mut i);
        let mut o = Self::sample_shift(&domain, &mut i);
        while r == o {o = Self::sample_shift(&domain, &mut i)}
        (r, o)
    }

    // evaluate witness polynomials over domains
    pub fn evaluate
    (
        &self,
        l: &DensePolynomial<F>,
        r: &DensePolynomial<F>,
        o: &DensePolynomial<F>,
        z: &DensePolynomial<F>,
    ) -> WitnessOverDomains<F>
    {
        // compute shifted witness polynomials
        let l4 = l.evaluate_over_domain_by_ref(self.domain.d4);
        let r4 = r.evaluate_over_domain_by_ref(self.domain.d4);
        let o4 = o.evaluate_over_domain_by_ref(self.domain.d4);
        let z4 = DensePolynomial::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap());

        let l8 = l.evaluate_over_domain_by_ref(self.domain.d8);
        let r8 = r.evaluate_over_domain_by_ref(self.domain.d8);
        let o8 = o.evaluate_over_domain_by_ref(self.domain.d8);
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        WitnessOverDomains
        {
            d4: WitnessShifts
            {
                next: WitnessEvals
                {
                    l: l4.shift(4),
                    r: r4.shift(4),
                    o: o4.shift(4),
                    z: z4.clone() // dummy evaluation
                },
                this: WitnessEvals
                {
                    l: l4,
                    r: r4,
                    o: o4,
                    z: z4 // dummy evaluation
                },
            },
            d8: WitnessShifts
            {
                next: WitnessEvals
                {
                    l: l8.shift(8),
                    r: r8.shift(8),
                    o: o8.shift(8),
                    z: z8.shift(8),
                },
                this: WitnessEvals
                {
                    l: l8,
                    r: r8,
                    o: o8,
                    z: z8,
                },
            },
        }
    }
}
