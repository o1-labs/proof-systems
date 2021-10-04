/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use crate::domains::EvaluationDomains;
use crate::gate::{CircuitGate, GateType};
use crate::gates::poseidon::*;
pub use crate::polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts};
use crate::wires::*;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::UVPolynomial;
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use blake2::{Blake2b, Digest};
use o1_utils::ExtendedEvaluations;
use oracle::poseidon::ArithmeticSpongeParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConstraintSystem<F: FftField> {
    // Basics
    // ------
    /// number of public inputs
    pub public: usize,
    /// evaluation domains
    #[serde(bound = "EvaluationDomains<F>: Serialize + DeserializeOwned")]
    pub domain: EvaluationDomains<F>,
    /// circuit gates
    #[serde(bound = "CircuitGate<F>: Serialize + DeserializeOwned")]
    pub gates: Vec<CircuitGate<F>>,

    // Polynomials over the monomial base
    // ----------------------------------
    /// permutation polynomial array
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmam: [DP<F>; PERMUTS],
    /// zero-knowledge polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpm: DP<F>,

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// linear wire constraint polynomial
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; GENERICS]")]
    pub qwm: [DP<F>; GENERICS],
    /// multiplication polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub qmm: DP<F>,
    /// constant wire polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub qc: DP<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// round constant polynomials
    #[serde_as(as = "[[o1_utils::serialization::SerdeAs; SPONGE_WIDTH]; ROUNDS_PER_ROW]")]
    pub rcm: [[DP<F>; SPONGE_WIDTH]; ROUNDS_PER_ROW],
    /// poseidon constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub psm: DP<F>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub addm: DP<F>,
    /// EC point doubling constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub doublem: DP<F>,
    /// mulm constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mulm: DP<F>,
    /// emulm constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emulm: DP<F>,

    //
    // Polynomials over lagrange base
    //

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// left input wire polynomial over domain.d4
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; GENERICS]")]
    pub qwl: [E<F, D<F>>; GENERICS],
    /// multiplication evaluations over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub qml: E<F, D<F>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; PERMUTS]")]
    pub sigmal1: [Vec<F>; PERMUTS],
    /// permutation polynomial array evaluations over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal8: [E<F, D<F>>; PERMUTS],
    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon selector over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ps4: E<F, D<F>>,
    /// poseidon selector over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ps8: E<F, D<F>>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition selector evaluations w over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub addl: E<F, D<F>>,
    /// EC point doubling selector evaluations w over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub doubl8: E<F, D<F>>,
    /// EC point doubling selector evaluations w over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub doubl4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mull4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mull8: E<F, D<F>>,
    /// endoscalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emull: E<F, D<F>>,

    // Constant polynomials
    // --------------------
    /// 1-st Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l1: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d4
    // TODO(mimoo): be consistent with the paper/spec, call it L1 here or call it L0 there
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l04: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l08: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero4: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero8: E<F, D<F>>,
    /// zero-knowledge polynomial over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpl: E<F, D<F>>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [F; PERMUTS],
    /// coefficient for the group endomorphism
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endo: F,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fr_sponge_params: ArithmeticSpongeParams<F>,
}

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
pub fn zk_w3<F: FftField>(domain: D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 3])
}

/// Computes the zero-knowledge polynomial for blinding the permutation polynomial: `(x-w^{n-k})(x-w^{n-k-1})...(x-w^n)`.
/// Currently, we use k = 3 for 2 blinding factors,
/// see https://www.plonk.cafe/t/noob-questions-plonk-paper/73
pub fn zk_polynomial<F: FftField>(domain: D<F>) -> DP<F> {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    // (x-w3)(x-w2)(x-w1) =
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w1w2 = w1 * &w2;
    DP::from_coefficients_slice(&[
        -w1w2 * &w3,                      // 1
        w1w2 + &(w1 * &w3) + &(w3 * &w2), // x
        -w1 - &w2 - &w3,                  // x^2
        F::one(),                         // x^3
    ])
}

/// Represents an error found when verifying a witness with a gate
#[derive(Debug)]
pub enum GateError {
    /// Some connected wires have different values
    DisconnectedWires(Wire, Wire),
    /// A public gate was incorrectly connected
    IncorrectPublic(usize),
    /// A specific gate did not verify correctly
    Custom { row: usize, err: String },
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// creates a constraint system from a vector of gates ([CircuitGate]), some sponge parameters ([ArithmeticSpongeParams]), and the number of public inputs.
    pub fn create(
        mut gates: Vec<CircuitGate<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self> {
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        // +3 on gates.len() here to ensure that we have room for the zero-knowledge entries of the permutation polynomial
        // see https://minaprotocol.com/blog/a-more-efficient-approach-to-zero-knowledge-for-plonk
        let domain = EvaluationDomains::<F>::create(gates.len() + 3)?;
        assert!(domain.d1.size > 3);

        // pre-compute all the elements
        let mut sid = domain.d1.elements().map(|elm| elm).collect::<Vec<_>>();

        // sample the coordinate shifts
        // TODO(mimoo): should we check that the shifts are all different?
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
        for (row, gate) in gates.iter().enumerate() {
            for col in 0..PERMUTS {
                let wire = gate.wires[col];
                sigmal1[col][row] = s[wire.col][wire.row];
            }
        }

        let sigmam: [DP<F>; PERMUTS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(sigmal1[i].clone(), domain.d1).interpolate()
        });

        let mut s = sid[0..2].to_vec(); // TODO(mimoo): why do we do that?
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
                        gate.c[COLUMNS]
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
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS]) -> Result<(), GateError> {
        let left_wire = vec![F::one(), F::zero(), F::zero(), F::zero(), F::zero()];

        for (row, gate) in self.gates.iter().enumerate() {
            // check if wires are connected
            for col in 0..COLUMNS {
                let wire = gate.wires[col];
                if witness[col][row] != witness[wire.col][wire.row] {
                    return Err(GateError::DisconnectedWires(
                        Wire { col, row },
                        Wire {
                            col: wire.col,
                            row: wire.row,
                        },
                    ));
                }
            }

            // for public gates, only the left wire is toggled
            if row < self.public {
                if gate.c != left_wire {
                    return Err(GateError::IncorrectPublic(row));
                }
            }

            gate.verify(witness, &self)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        return Ok(());
    }

    /// sample coordinate shifts deterministically
    pub fn sample_shift(domain: &D<F>, i: &mut u32) -> F {
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
                    // TODO(mimoo): change z to an Option? Or maybe not, we might actually need this dummy evaluation in the aggregated evaluation proof
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_ff::{FftField, SquareRootField};
    use mina_curves::pasta::fp::Fp;

    impl<F: FftField + SquareRootField> ConstraintSystem<F> {
        pub fn for_testing(
            sponge_params: ArithmeticSpongeParams<F>,
            gates: Vec<CircuitGate<F>>,
        ) -> Self {
            let public = 0;
            ConstraintSystem::<F>::create(gates, sponge_params, public).unwrap()
        }
    }

    impl ConstraintSystem<Fp> {
        pub fn fp_for_testing(gates: Vec<CircuitGate<Fp>>) -> Self {
            let fp_sponge_params = oracle::pasta::fp::params();
            Self::for_testing(fp_sponge_params, gates)
        }
    }
}
