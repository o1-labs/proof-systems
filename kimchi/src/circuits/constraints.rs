//! This module implements Plonk circuit constraint primitive.
use super::lookup::runtime_tables::RuntimeTableCfg;
use crate::{
    circuits::{
        domain_constant_evaluation::DomainConstantEvaluations,
        domains::EvaluationDomains,
        gate::{CircuitGate, GateType},
        lookup::{index::LookupConstraintSystem, tables::LookupTable},
        polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
        polynomials::permutation::{Shifts, ZK_ROWS},
        polynomials::range_check,
        wires::*,
    },
    curve::KimchiCurve,
    error::SetupError,
};
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use o1_utils::ExtendedEvaluations;
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::{collections::HashSet, sync::Arc};

//
// ConstraintSystem
//

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConstraintSystem<G: KimchiCurve> {
    // Basics
    // ------
    /// number of public inputs
    pub public: usize,
    /// evaluation domains
    #[serde(bound = "EvaluationDomains<G::ScalarField>: Serialize + DeserializeOwned")]
    pub domain: EvaluationDomains<G::ScalarField>,
    /// circuit gates
    #[serde(bound = "CircuitGate<G::ScalarField>: Serialize + DeserializeOwned")]
    pub gates: Vec<CircuitGate<G::ScalarField>>,

    // Polynomials over the monomial base
    // ----------------------------------
    /// permutation polynomial array
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmam: [DP<G::ScalarField>; PERMUTS],

    // Coefficient polynomials. These define constant that gates can use as they like.
    // ---------------------------------------
    /// coefficients polynomials in evaluation form
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficients8: [E<G::ScalarField, D<G::ScalarField>>; COLUMNS],

    // Generic constraint selector polynomials
    // ---------------------------------------
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub genericm: DP<G::ScalarField>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub psm: DP<G::ScalarField>,

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// multiplication evaluations over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic4: E<G::ScalarField, D<G::ScalarField>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal1: [E<G::ScalarField, D<G::ScalarField>>; PERMUTS],
    /// permutation polynomial array evaluations over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal8: [E<G::ScalarField, D<G::ScalarField>>; PERMUTS],
    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<G::ScalarField>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon selector over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ps8: E<G::ScalarField, D<G::ScalarField>>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition selector evaluations w over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub complete_addl4: E<G::ScalarField, D<G::ScalarField>>,
    /// scalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mull8: E<G::ScalarField, D<G::ScalarField>>,
    /// endoscalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emull: E<G::ScalarField, D<G::ScalarField>>,
    /// ChaCha indexes
    #[serde_as(as = "Option<[o1_utils::serialization::SerdeAs; 4]>")]
    pub chacha8: Option<[E<G::ScalarField, D<G::ScalarField>>; 4]>,
    /// EC point addition selector evaluations w over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalar8: E<G::ScalarField, D<G::ScalarField>>,

    /// Range check gate selector polynomials
    #[serde(
        bound = "Vec<range_check::SelectorPolynomial<G::ScalarField>>: Serialize + DeserializeOwned"
    )]
    pub range_check_selector_polys: Vec<range_check::SelectorPolynomial<G::ScalarField>>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [G::ScalarField; PERMUTS],
    /// coefficient for the group endomorphism
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endo: G::ScalarField,

    /// random oracle argument parameters
    //#[serde(skip)]
    //pub fr_sponge_params: ArithmeticSpongeParams<G::ScalarField>,

    /// lookup constraint system
    #[serde(bound = "LookupConstraintSystem<G::ScalarField>: Serialize + DeserializeOwned")]
    pub lookup_constraint_system: Option<LookupConstraintSystem<G::ScalarField>>,

    /// precomputes
    #[serde(skip)]
    precomputations: OnceCell<Arc<DomainConstantEvaluations<G::ScalarField>>>,
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

pub struct Builder<G: KimchiCurve> {
    gates: Vec<CircuitGate<G::ScalarField>>,
    //sponge_params: ArithmeticSpongeParams<G::ScalarField>,
    public: usize,
    lookup_tables: Vec<LookupTable<G::ScalarField>>,
    runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
    precomputations: Option<Arc<DomainConstantEvaluations<G::ScalarField>>>,
}

impl<G: KimchiCurve> ConstraintSystem<G> {
    /// Initializes the [ConstraintSystem<F>] on input `gates` and `fr_sponge_params`.
    /// Returns a [Builder<F>]
    /// It also defaults to the following values of the builder:
    /// - `public: 0`
    /// - `lookup_tables: vec![]`,
    /// - `runtime_tables: None`,
    /// - `precomputations: None`,
    ///
    /// How to use it:
    /// 1. Create your instance of your builder for the constraint system using `crate(gates, sponge params)`
    /// 2. Iterativelly invoke any desired number of steps: `public(), lookup(), runtime(), precomputations()``
    /// 3. Finally call the `build()` method and unwrap the `Result` to obtain your `ConstraintSystem`
    pub fn create(
        gates: Vec<CircuitGate<G::ScalarField>>,
        //sponge_params: ArithmeticSpongeParams<G::ScalarField>,
    ) -> Builder<G> {
        Builder {
            gates,
            //sponge_params,
            public: 0,
            lookup_tables: vec![],
            runtime_tables: None,
            precomputations: None,
        }
    }

    pub fn precomputations(&self) -> &Arc<DomainConstantEvaluations<G::ScalarField>> {
        self.precomputations
            .get_or_init(|| Arc::new(DomainConstantEvaluations::create(self.domain).unwrap()))
    }

    pub fn set_precomputations(
        &self,
        precomputations: Arc<DomainConstantEvaluations<G::ScalarField>>,
    ) {
        self.precomputations
            .set(precomputations)
            .expect("Precomputation has been set before");
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    ///     witness: wire assignement witness
    ///     RETURN: verification status
    pub fn verify(
        &self,
        witness: &[Vec<G::ScalarField>; COLUMNS],
        public: &[G::ScalarField],
    ) -> Result<(), GateError> {
        // pad the witness
        let pad = vec![<G::ScalarField>::zero(); self.domain.d1.size() - witness[0].len()];
        let witness: [Vec<G::ScalarField>; COLUMNS] = array_init(|i| {
            let mut w = witness[i].to_vec();
            w.extend_from_slice(&pad);
            w
        });

        // check each rows' wiring
        for (row, gate) in self.gates.iter().enumerate() {
            // check if wires are connected
            for col in 0..PERMUTS {
                let wire = gate.wires[col];

                if wire.col >= PERMUTS {
                    return Err(GateError::Custom {
                        row,
                        err: format!(
                            "a wire can only be connected to the first {} columns",
                            PERMUTS
                        ),
                    });
                }

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
            if row < self.public && gate.coeffs[0] != <G::ScalarField>::one() {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify(row, &witness, self, public)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        Ok(())
    }

    /// evaluate witness polynomials over domains
    pub fn evaluate(
        &self,
        w: &[DP<G::ScalarField>; COLUMNS],
        z: &DP<G::ScalarField>,
    ) -> WitnessOverDomains<G::ScalarField> {
        // compute shifted witness polynomials
        let w8: [E<G::ScalarField, D<G::ScalarField>>; COLUMNS] =
            array_init(|i| w[i].evaluate_over_domain_by_ref(self.domain.d8));
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        let w4: [E<G::ScalarField, D<G::ScalarField>>; COLUMNS] = array_init(|i| {
            E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                (0..self.domain.d4.size)
                    .map(|j| w8[i].evals[2 * j as usize])
                    .collect(),
                self.domain.d4,
            )
        });
        let z4 = DP::<G::ScalarField>::zero()
            .evaluate_over_domain_by_ref(D::<G::ScalarField>::new(1).unwrap());

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

impl<G: KimchiCurve> Builder<G> {
    /// Set up the number of public inputs.
    /// If not invoked, it equals `0` by default.
    pub fn public(mut self, public: usize) -> Self {
        self.public = public;
        self
    }

    /// Set up the lookup tables.
    /// If not invoked, it is `vec![]` by default.
    ///
    /// **Warning:** you have to make sure that the IDs of the lookup tables,
    /// are unique and  not colliding with IDs of built-in lookup tables
    /// (see [crate::circuits::lookup::tables]).
    pub fn lookup(mut self, lookup_tables: Vec<LookupTable<G::ScalarField>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    /// Set up the runtime tables.
    /// If not invoked, it is `None` by default.
    ///
    /// **Warning:** you have to make sure that the IDs of the runtime lookup tables,
    /// are unique and not colliding with IDs of built-in lookup tables
    /// (see [crate::circuits::lookup::tables]).
    pub fn runtime(mut self, runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>) -> Self {
        self.runtime_tables = runtime_tables;
        self
    }

    /// Set up the shared precomputations.
    /// If not invoked, it is `None` by default.
    pub fn shared_precomputations(
        mut self,
        shared_precomputations: Arc<DomainConstantEvaluations<G::ScalarField>>,
    ) -> Self {
        self.precomputations = Some(shared_precomputations);
        self
    }

    /// Build the [ConstraintSystem] from a [Builder].
    pub fn build(self) -> Result<ConstraintSystem<G>, SetupError> {
        let mut gates = self.gates;
        let lookup_tables = self.lookup_tables;
        let runtime_tables = self.runtime_tables;

        //~ 1. If the circuit is less than 2 gates, abort.
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        //~ 2. Create a domain for the circuit. That is,
        //~    compute the smallest subgroup of the field that
        //~    has order greater or equal to `n + ZK_ROWS` elements.
        let domain = EvaluationDomains::<G::ScalarField>::create(gates.len() + ZK_ROWS as usize)?;

        assert!(domain.d1.size > ZK_ROWS);

        //~ 3. Pad the circuit: add zero gates to reach the domain size.
        let d1_size = domain.d1.size();
        let mut padding = (gates.len()..d1_size)
            .map(|i| {
                CircuitGate::<G::ScalarField>::zero(array_init(|j| Wire {
                    col: WIRES[j],
                    row: i,
                }))
            })
            .collect();
        gates.append(&mut padding);

        // Record which gates are used by this constraint system
        let mut circuit_gates_used = HashSet::<GateType>::default();
        gates.iter().for_each(|gate| {
            circuit_gates_used.insert(gate.typ);
        });

        //~ 4. sample the `PERMUTS` shifts.
        let shifts = Shifts::new(&domain.d1);

        // Precomputations
        // ===============
        // what follows are pre-computations.

        //
        // Permutation
        // -----------

        // compute permutation polynomials
        let mut sigmal1: [Vec<G::ScalarField>; PERMUTS] =
            array_init(|_| vec![<G::ScalarField>::zero(); domain.d1.size()]);

        for (row, gate) in gates.iter().enumerate() {
            for (cell, sigma) in gate.wires.iter().zip(sigmal1.iter_mut()) {
                sigma[row] = shifts.cell_to_field(cell);
            }
        }

        let sigmal1: [_; PERMUTS] = {
            let [s0, s1, s2, s3, s4, s5, s6] = sigmal1;
            [
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s0, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s1, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s2, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s3, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s4, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s5, domain.d1),
                E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(s6, domain.d1),
            ]
        };

        let sigmam: [DP<G::ScalarField>; PERMUTS] =
            array_init(|i| sigmal1[i].clone().interpolate());

        let sigmal8 = array_init(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8));

        // Gates
        // -----
        //
        // Compute each gate's polynomial as
        // the polynomial that evaluates to 1 at $g^i$
        // where $i$ is the row where a gate is active.
        // Note: gates must be mutually exclusive.

        // poseidon gate
        let psm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.ps()).collect(),
            domain.d1,
        )
        .interpolate();
        let ps8 = psm.evaluate_over_domain_by_ref(domain.d8);

        // ECC gates
        let complete_addm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| G::ScalarField::from((gate.typ == GateType::CompleteAdd) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let complete_addl4 = complete_addm.evaluate_over_domain_by_ref(domain.d4);

        let mulm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.vbmul()).collect(),
            domain.d1,
        )
        .interpolate();
        let mull8 = mulm.evaluate_over_domain_by_ref(domain.d8);

        let emulm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.endomul()).collect(),
            domain.d1,
        )
        .interpolate();
        let emull = emulm.evaluate_over_domain_by_ref(domain.d8);

        let endomul_scalarm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| G::ScalarField::from((gate.typ == GateType::EndoMulScalar) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let endomul_scalar8 = endomul_scalarm.evaluate_over_domain_by_ref(domain.d8);

        // double generic gate
        let genericm = E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if matches!(gate.typ, GateType::Generic) {
                        <G::ScalarField>::one()
                    } else {
                        <G::ScalarField>::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();
        let generic4 = genericm.evaluate_over_domain_by_ref(domain.d4);

        // chacha gate
        let chacha8 = {
            use GateType::*;
            let has_chacha_gate = gates
                .iter()
                .any(|gate| matches!(gate.typ, ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal));
            if !has_chacha_gate {
                None
            } else {
                let a: [_; 4] = array_init(|i| {
                    let g = match i {
                        0 => ChaCha0,
                        1 => ChaCha1,
                        2 => ChaCha2,
                        3 => ChaChaFinal,
                        _ => panic!("Invalid index"),
                    };
                    E::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                        gates
                            .iter()
                            .map(|gate| {
                                if gate.typ == g {
                                    <G::ScalarField>::one()
                                } else {
                                    <G::ScalarField>::zero()
                                }
                            })
                            .collect(),
                        domain.d1,
                    )
                    .interpolate()
                    .evaluate_over_domain(domain.d8)
                });
                Some(a)
            }
        };

        // Range check constraint selector polynomials
        let range_check_selector_polys = {
            if !circuit_gates_used.is_disjoint(&range_check::circuit_gates().into_iter().collect())
            {
                range_check::selector_polynomials(&gates, &domain)
            } else {
                vec![]
            }
        };

        //
        // Coefficient
        // -----------
        //

        // coefficient polynomial
        let coefficientsm: [_; COLUMNS] = array_init(|i| {
            let padded = gates
                .iter()
                .map(|gate| {
                    gate.coeffs
                        .get(i)
                        .cloned()
                        .unwrap_or_else(<G::ScalarField>::zero)
                })
                .collect();
            let eval = E::from_vec_and_domain(padded, domain.d1);
            eval.interpolate()
        });
        // TODO: This doesn't need to be degree 8 but that would require some changes in expr
        let coefficients8 = array_init(|i| coefficientsm[i].evaluate_over_domain_by_ref(domain.d8));

        //
        // Lookup
        // ------
        let lookup_constraint_system =
            LookupConstraintSystem::create(&gates, lookup_tables, runtime_tables, &domain)
                .map_err(|e| SetupError::ConstraintSystem(e.to_string()))?;

        let sid = shifts.map[0].clone();

        // TODO: remove endo as a field
        let endo = <G::ScalarField>::zero();

        let domain_constant_evaluation = OnceCell::new();

        let constraints = ConstraintSystem {
            chacha8,
            endomul_scalar8,
            domain,
            public: self.public,
            sid,
            sigmal1,
            sigmal8,
            sigmam,
            genericm,
            generic4,
            coefficients8,
            ps8,
            psm,
            complete_addl4,
            mull8,
            emull,
            range_check_selector_polys,
            gates,
            shift: shifts.shifts,
            endo,
            //fr_sponge_params: self.sponge_params,
            lookup_constraint_system,
            precomputations: domain_constant_evaluation,
        };

        match self.precomputations {
            Some(t) => {
                constraints.set_precomputations(t);
            }
            None => {
                constraints.precomputations();
            }
        }
        Ok(constraints)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mina_curves::pasta::fp::Fp;
    use mina_curves::pasta::vesta::Affine;

    impl<G: KimchiCurve> ConstraintSystem<G> {
        pub fn for_testing(
            //sponge_params: ArithmeticSpongeParams<G::ScalarField>,
            gates: Vec<CircuitGate<G::ScalarField>>,
        ) -> Self {
            let public = 0;
            // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
            ConstraintSystem::<G>::create(gates)
                .public(public)
                .build()
                .unwrap()
        }
    }

    impl ConstraintSystem<Affine> {
        pub fn fp_for_testing(gates: Vec<CircuitGate<Fp>>) -> Self {
            //let fp_sponge_params = oracle::pasta::fp_kimchi::params();
            Self::for_testing(gates)
        }
    }
}
