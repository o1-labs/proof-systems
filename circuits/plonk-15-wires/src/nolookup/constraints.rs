/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use crate::domains::EvaluationDomains;
use crate::gate::{LookupInfo, CircuitGate, GateType};
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

    // Coefficient polynomials. These define constant that gates can use as they like.
    // ---------------------------------------

    /// coefficients polynomials in coefficient form
    pub coefficientsm: [DP<F>; COLUMNS],
    /// coefficients polynomials in evaluation form
    pub coefficients4: [E<F, D<F>>; COLUMNS],

    // Generic constraint selector polynomials
    // ---------------------------------------
    pub genericm: DP<F>,

    // Poseidon selector polynomials
    // -----------------------------
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
    /// multiplication evaluations over domain.d4
    pub generic4: E<F, D<F>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    pub sigmal1: [E<F, D<F>>; PERMUTS],
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
    /// ChaCha indexes
    pub chacha8: Option<[E<F, D<F>>; 4]>,

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

    /// Lookup tables
    pub dummy_lookup_values: Vec<Vec<F>>,
    pub lookup_tables: Vec<Vec<DP<F>>>,
    pub lookup_tables8: Vec<Vec<E<F, D<F>>>>,
    pub lookup_table_lengths: Vec<usize>,

    /// Lookup selectors:
    /// For each kind of lookup-pattern, we have a selector that's
    /// 1 at the rows where that pattern should be enforced, and 1 at
    /// all other rows.
    pub lookup_selectors: Vec<E<F, D<F>>>,
}

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
pub fn zk_w3<F: FftField>(domain: D<F>) -> F {
    domain.group_gen.pow(&[domain.size - 3])
}

pub fn eval_zk_polynomial<F: FftField>(domain: D<F>, x: F) -> F {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    (x - w1) * (x - w2) * (x - w3)
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
        lookup_tables: Vec< Vec<Vec<F>> >,
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

        let sigmal1 : [_ ; PERMUTS] = {
            let [s0, s1, s2, s3, s4, s5, s6] = sigmal1;
            [ E::<F, D<F>>::from_vec_and_domain(s0, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s1, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s2, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s3, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s4, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s5, domain.d1),
              E::<F, D<F>>::from_vec_and_domain(s6, domain.d1) ]
        };

        let sigmam: [DP<F>; PERMUTS] = array_init(|i| {
            sigmal1[i].clone().interpolate()
        });

        let mut s = sid[0..2].to_vec(); // TODO(mimoo): why do we do that?
        sid.append(&mut s);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);

        // compute generic constraint polynomials

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

        let genericm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.generic()).collect(),
            domain.d1,
        )
        .interpolate();
        let generic4 = genericm.evaluate_over_domain_by_ref(domain.d4);

        let chacha8 = {
            use GateType::*;
            let has_chacha_gate =
                gates.iter().any(|gate| {
                    match gate.typ {
                        ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => true,
                        _ => false
                    }
                });
            if !has_chacha_gate {
                None
            } else {
                let a : [_; 4] =
                    array_init(|i| {
                        let g =
                            match i {
                                0 => ChaCha0,
                                1 => ChaCha1,
                                2 => ChaCha2,
                                3 => ChaChaFinal,
                                _ => panic!("Invalid index")
                            };
                        E::<F, D<F>>::from_vec_and_domain(
                            gates
                                .iter()
                                .map(|gate| {
                                    if gate.typ == g {
                                        F::one()
                                    } else {
                                        F::zero()
                                    }
                                })
                                .collect(),
                            domain.d1)
                            .interpolate()
                            .evaluate_over_domain(domain.d8)
                    });
                Some(a)
            }
        };

        let coefficientsm: [_; COLUMNS] =
            array_init(|i| {
                E::<F, D<F>>::from_vec_and_domain(
                    gates.iter().map(|gate| {
                        if i < gate.c.len() {
                            gate.c[i]
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
                    domain.d1)
                .interpolate()
            });
        let coefficients4 = array_init(|i| coefficientsm[i].evaluate_over_domain_by_ref(domain.d4));

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
        // TODO: These are all unnecessary. Remove
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

        let lookup_table_lengths: Vec<_> = lookup_tables.iter().map(|v| v[0].len()).collect();
        let dummy_lookup_values : Vec<Vec<F>> =
            lookup_tables.iter()
            .map(|cols| cols.iter().map(|c| c[c.len() - 1]).collect())
            .collect();

        let lookup_tables : Vec<Vec<DP<F>>> =
            lookup_tables
            .into_iter()
            .zip(dummy_lookup_values.iter())
            .map(|(t, dummy)| {
                t.into_iter().enumerate().map(|(i, mut col)| {
                    let d = dummy[i];
                    col.extend((0..(n - col.len())).map(|_| d));
                    E::<F, D<F>>::from_vec_and_domain(col, domain.d1).interpolate()
                }).collect()
            }).collect();
        let lookup_tables8 = lookup_tables.iter().map(|t| {
            t.iter().map(|col| col.evaluate_over_domain_by_ref(domain.d8)).collect()
        }).collect();

        let lookup_info = LookupInfo::<F>::create();

        // return result
        Some(ConstraintSystem {
            chacha8,
            lookup_selectors:
                if lookup_info.lookup_used(&gates).is_some() {
                    LookupInfo::<F>::create().selector_polynomials(domain, &gates)
                } else {
                    vec![]
                },
            dummy_lookup_values,
            lookup_table_lengths,
            lookup_tables8,
            lookup_tables,
            domain,
            public,
            sid,
            sigmal1,
            sigmal8,
            sigmam,
            genericm,
            generic4,
            coefficientsm,
            coefficients4,
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
            ConstraintSystem::<F>::create(gates, vec![], sponge_params, public).unwrap()
        }
    }

    impl ConstraintSystem<Fp> {
        pub fn fp_for_testing(gates: Vec<CircuitGate<Fp>>) -> Self {
            let fp_sponge_params = oracle::pasta::fp::params();
            Self::for_testing(fp_sponge_params, gates)
        }
    }
}
