/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use crate::domains::EvaluationDomains;
use crate::gate::{CircuitGate, GateType};
use crate::gates::poseidon::*;
pub use crate::polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts};
use crate::wires::*;
use algebra::{FftField, SquareRootField};
use array_init::array_init;
use blake2::{Blake2b, Digest};
use ff_fft::{
    DensePolynomial as DP, EvaluationDomain, Evaluations as E, Radix2EvaluationDomain as D,
};
use oracle::poseidon::ArithmeticSpongeParams;
use oracle::utils::EvalUtils;

#[derive(Clone)]
pub struct ConstraintSystem<F: FftField> {
    // Basics
    // ------
    /// number of public inputs
    pub public: usize,
    /// evaluation domains
    pub domain: EvaluationDomains<F>,
    /// circuit gates
    pub gates: Vec<CircuitGate<F>>,

    // Polynomials over the monomial base
    // ----------------------------------
    /// permutation polynomial array
    pub sigmam: [DP<F>; PERMUTS],
    /// zero-knowledge polynomial
    pub zkpm: DP<F>,

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// linear wire constraint polynomial
    pub qwm: [DP<F>; GENERICS],
    /// multiplication polynomial
    pub qmm: DP<F>,
    /// constant wire polynomial
    pub qc: DP<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// round constant polynomials
    pub rcm: [[DP<F>; SPONGE_WIDTH]; ROUNDS_PER_ROW],
    /// poseidon constraint selector polynomial
    pub psm: DP<F>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition constraint selector polynomial
    pub addm: DP<F>,
    /// EC point doubling constraint selector polynomial
    pub doublem: DP<F>,
    /// mulm constraint selector polynomial
    pub mulm: DP<F>,
    /// emulm constraint selector polynomial
    pub emulm: DP<F>,

    //
    // Polynomials over lagrange base
    //

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// left input wire polynomial over domain.d4
    pub qwl: [E<F, D<F>>; GENERICS],
    /// multiplication evaluations over domain.d4
    pub qml: E<F, D<F>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    pub sigmal1: [Vec<F>; PERMUTS],
    /// permutation polynomial array evaluations over domain d8
    pub sigmal8: [E<F, D<F>>; PERMUTS],
    /// SID polynomial
    pub sid: Vec<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon selector over domain.d4
    pub ps4: E<F, D<F>>,
    /// poseidon selector over domain.d8
    pub ps8: E<F, D<F>>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition selector evaluations w over domain.d4
    pub addl: E<F, D<F>>,
    /// EC point doubling selector evaluations w over domain.d8
    pub doubl8: E<F, D<F>>,
    /// EC point doubling selector evaluations w over domain.d4
    pub doubl4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d4
    pub mull4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d8
    pub mull8: E<F, D<F>>,
    /// endoscalar multiplication selector evaluations over domain.d8
    pub emull: E<F, D<F>>,

    // Constant polynomials
    // --------------------
    /// 1-st Lagrange evaluated over domain.d8
    pub l1: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d4
    // TODO(mimoo): be consistent with the paper/spec, call it L1 here or call it L0 there
    pub l04: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d8
    pub l08: E<F, D<F>>,
    /// zero evaluated over domain.d8
    pub zero4: E<F, D<F>>,
    /// zero evaluated over domain.d8
    pub zero8: E<F, D<F>>,
    /// zero-knowledge polynomial over domain.d8
    pub zkpl: E<F, D<F>>,

    /// wire coordinate shifts
    pub shift: [F; PERMUTS],
    /// coefficient for the group endomorphism
    pub endo: F,

    /// random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<F>,
}

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
// TODO(mimoo): ensure that this cannot be used by a circuit
pub fn zk_w3<F: FftField>(domain: D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 3])
}

pub fn zk_polynomial<F: FftField>(domain: D<F>) -> DP<F> {
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    DP::from_coefficients_slice(&[
        -w1 * &w2 * &w3,
        (w1 * &w2) + &(w1 * &w3) + &(w3 * &w2),
        -w1 - &w2 - &w3,
        F::one(),
    ])
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// creates a constraint system from a vector of gates ([CircuitGate]), some sponge parameters ([ArithmeticSpongeParams]), and the number of public inputs.
    pub fn create(
        mut gates: Vec<CircuitGate<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self> {
        let domain = EvaluationDomains::<F>::create(gates.len())?;
        let mut sid = domain.d1.elements().map(|elm| elm).collect::<Vec<_>>();

        // sample the coordinate shifts
        let shift = Self::sample_shifts(&domain.d1, PERMUTS - 1);
        let shift: [F; PERMUTS] = array_init(|i| if i == 0 { F::one() } else { shift[i - 1] });

        let n = domain.d1.size();
        let mut padding = (gates.len()..n)
            .map(|i| {
                CircuitGate::<F>::zero(
                    i,
                    array_init(|j| Wire {
                        col: WIRES[j],
                        row: i,
                    }),
                )
            })
            .collect();
        gates.append(&mut padding);

        let s: [std::vec::Vec<F>; PERMUTS] =
            array_init(|i| domain.d1.elements().map(|elm| shift[i] * &elm).collect());
        let mut sigmal1 = s.clone();

        // compute permutation polynomials
        gates.iter().enumerate().for_each(|(i, _)| {
            (0..PERMUTS).for_each(|j| {
                let wire = gates[i].wires[j];
                sigmal1[j][i] = s[wire.col][wire.row]
            })
        });
        let sigmam: [DP<F>; PERMUTS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(sigmal1[i].clone(), domain.d1).interpolate()
        });

        let mut s = sid[0..2].to_vec();
        sid.append(&mut s);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);

        // compute generic constraint polynomials
        let qwm: [DP<F>; GENERICS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(
                gates
                    .iter()
                    .map(|gate| {
                        if gate.typ == GateType::Generic {
                            gate.c[WIRES[i]]
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
                domain.d1,
            )
            .interpolate()
        });
        let qmm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if gate.typ == GateType::Generic {
                        gate.c[GENERICS]
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();

        // compute poseidon constraint polynomials
        let psm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.ps()).collect(),
            domain.d1,
        )
        .interpolate();

        // compute ECC arithmetic constraint polynomials
        let addm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.add()).collect(),
            domain.d1,
        )
        .interpolate();
        let doublem = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.double()).collect(),
            domain.d1,
        )
        .interpolate();
        let mulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.vbmul()).collect(),
            domain.d1,
        )
        .interpolate();
        let emulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.endomul()).collect(),
            domain.d1,
        )
        .interpolate();

        let sigmal8 = array_init(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8));

        // generic constraint polynomials
        let qwl = array_init(|i| qwm[i].evaluate_over_domain_by_ref(domain.d4));
        let qml = qmm.evaluate_over_domain_by_ref(domain.d4);
        let qc = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if gate.typ == GateType::Generic {
                        gate.c[COLUMNS + 1]
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();

        // poseidon constraint polynomials
        let rcm = array_init(|round| {
            array_init(|col| {
                E::<F, D<F>>::from_vec_and_domain(
                    gates
                        .iter()
                        .map(|gate| {
                            if gate.typ == GateType::Poseidon {
                                gate.rc()[round][col]
                            } else {
                                F::zero()
                            }
                        })
                        .collect(),
                    domain.d1,
                )
                .interpolate()
            })
        });

        let ps4 = psm.evaluate_over_domain_by_ref(domain.d4);
        let ps8 = psm.evaluate_over_domain_by_ref(domain.d8);

        // ECC arithmetic constraint polynomials
        let addl = addm.evaluate_over_domain_by_ref(domain.d4);
        let doubl8 = doublem.evaluate_over_domain_by_ref(domain.d8);
        let doubl4 = doublem.evaluate_over_domain_by_ref(domain.d4);
        let mull4 = mulm.evaluate_over_domain_by_ref(domain.d4);
        let mull8 = mulm.evaluate_over_domain_by_ref(domain.d8);
        let emull = emulm.evaluate_over_domain_by_ref(domain.d8);

        // constant polynomials
        let l1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        let l04 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size as usize], domain.d4);
        let l08 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size as usize], domain.d8);
        let zero4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d4.size as usize], domain.d4);
        let zero8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d8.size as usize], domain.d8);
        let zkpl = zkpm.evaluate_over_domain_by_ref(domain.d8);

        // endo
        let endo = F::zero();

        // return result
        Some(ConstraintSystem {
            domain,
            public,
            sid,
            sigmal1,
            sigmal8,
            sigmam,
            qwl,
            qml,
            qwm,
            qmm,
            qc,
            rcm,
            ps4,
            ps8,
            psm,
            addl,
            addm,
            doubl8,
            doubl4,
            doublem,
            mull4,
            mull8,
            mulm,
            emull,
            emulm,
            l1,
            l04,
            l08,
            zero4,
            zero8,
            zkpl,
            zkpm,
            gates,
            shift,
            endo,
            fr_sponge_params,
        })
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    ///     witness: wire assignement witness
    ///     RETURN: verification status
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS]) -> bool {
        // TODO: what does this represent? guess: q_L is set, q_R, q_M, q_C, and q_O are not
        let p = vec![F::one(), F::zero(), F::zero(), F::zero(), F::zero()];

        (0..self.gates.len()).all(|row|
                // verify permutation consistency
                (0..COLUMNS).all(|col|
                {
                    let wire = self.gates[row].wires[col];
                    witness[col][row] == witness[wire.col][wire.row]
                })
                &&
                // verify witness against constraints
                if row < self.public {
                    // TODO: shouldn't we also check that the gate is of type zero?
                    self.gates[row].c == p
                } else {
                    self.gates[row].verify(witness, &self)
                })
    }

    /// sample coordinate shifts deterministically
    pub fn sample_shift(domain: &D<F>, i: &mut u32) -> F {
        let mut h = Blake2b::new();
        h.input(
            &{
                *i += 1;
                *i
            }
            .to_be_bytes(),
        );
        let mut r = F::from_random_bytes(&h.result()[..31]).unwrap();
        while r.legendre().is_qnr() == false || domain.evaluate_vanishing_polynomial(r).is_zero() {
            let mut h = Blake2b::new();
            h.input(
                &{
                    *i += 1;
                    *i
                }
                .to_be_bytes(),
            );
            r = F::from_random_bytes(&h.result()[..31]).unwrap();
        }
        r
    }

    pub fn sample_shifts(domain: &D<F>, len: usize) -> Vec<F> {
        let mut i: u32 = 7;
        let mut shifts = Vec::with_capacity(len);
        while shifts.len() < len {
            let mut o = Self::sample_shift(&domain, &mut i);
            while shifts.iter().filter(|&r| o == *r).count() > 0 {
                o = Self::sample_shift(&domain, &mut i)
            }
            shifts.push(o)
        }
        shifts
    }

    /// evaluate witness polynomials over domains
    pub fn evaluate(&self, w: &[DP<F>; COLUMNS], z: &DP<F>) -> WitnessOverDomains<F> {
        println!("evaluate(w, z) -> WitnessOverDomains");
        // compute shifted witness polynomials
        let w8: [E<F, D<F>>; COLUMNS] =
            array_init(|i| w[i].evaluate_over_domain_by_ref(self.domain.d8));
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        let w4: [E<F, D<F>>; COLUMNS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(
                (0..self.domain.d4.size)
                    .map(|j| w8[i].evals[2 * j as usize])
                    .collect(),
                self.domain.d4,
            )
        });
        let z4 = DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap());

        WitnessOverDomains {
            d4: WitnessShifts {
                next: WitnessEvals {
                    w: array_init(|i| w4[i].shift(4)),
                    z: z4.clone(), // dummy evaluation
                },
                this: WitnessEvals {
                    w: w4,
                    z: z4, // dummy evaluation
                },
            },
            d8: WitnessShifts {
                next: WitnessEvals {
                    w: array_init(|i| w8[i].shift(8)),
                    z: z8.shift(8),
                },
                this: WitnessEvals { w: w8, z: z8 },
            },
        }
    }
}
