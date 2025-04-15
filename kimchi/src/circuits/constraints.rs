//! This module implements Plonk circuit constraint primitive.
use super::lookup::runtime_tables::RuntimeTableCfg;
use crate::{
    circuits::{
        domain_constant_evaluation::DomainConstantEvaluations,
        domains::EvaluationDomains,
        gate::{CircuitGate, GateType},
        lookup::{
            index::LookupConstraintSystem,
            lookups::{LookupFeatures, LookupPatterns},
            tables::{GateLookupTables, LookupTable},
        },
        polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
        polynomials::permutation::Shifts,
        wires::*,
    },
    curve::KimchiCurve,
    error::{DomainCreationError, SetupError},
    o1_utils::lazy_cache::LazyCache,
    prover_index::ProverIndex,
};
use ark_ff::{PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use o1_utils::ExtendedEvaluations;
use poly_commitment::OpenProof;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::{array, default::Default, sync::Arc};

//
// ConstraintSystem
//

/// Flags for optional features in the constraint system
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub struct FeatureFlags {
    /// RangeCheck0 gate
    pub range_check0: bool,
    /// RangeCheck1 gate
    pub range_check1: bool,
    /// Foreign field addition gate
    pub foreign_field_add: bool,
    /// Foreign field multiplication gate
    pub foreign_field_mul: bool,
    /// XOR gate
    pub xor: bool,
    /// ROT gate
    pub rot: bool,
    /// Lookup features
    pub lookup_features: LookupFeatures,
}

impl Default for FeatureFlags {
    /// Returns an instance with all features disabled.
    fn default() -> FeatureFlags {
        FeatureFlags {
            range_check0: false,
            range_check1: false,
            lookup_features: LookupFeatures {
                patterns: LookupPatterns {
                    xor: false,
                    lookup: false,
                    range_check: false,
                    foreign_field_mul: false,
                },
                joint_lookup_used: false,
                uses_runtime_tables: false,
            },
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
        }
    }
}

/// The polynomials representing evaluated columns, in coefficient form.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EvaluatedColumnCoefficients<F: PrimeField> {
    /// permutation coefficients
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub permutation_coefficients: [DP<F>; PERMUTS],

    /// gate coefficients
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficients: [DP<F>; COLUMNS],

    /// generic gate selector
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic_selector: DP<F>,

    /// poseidon gate selector
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub poseidon_selector: DP<F>,
}

/// The polynomials representing columns, in evaluation form.
/// The evaluations are expanded to the domain size required for their constraints.
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ColumnEvaluations<F: PrimeField> {
    /// permutation coefficients over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub permutation_coefficients8: [E<F, D<F>>; PERMUTS],

    /// coefficients over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficients8: [E<F, D<F>>; COLUMNS],

    /// generic selector over domain d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic_selector4: E<F, D<F>>,

    /// poseidon selector over domain d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub poseidon_selector8: E<F, D<F>>,

    /// EC point addition selector over domain d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub complete_add_selector4: E<F, D<F>>,

    /// scalar multiplication selector over domain d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mul_selector8: E<F, D<F>>,

    /// endoscalar multiplication selector over domain d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emul_selector8: E<F, D<F>>,

    /// EC point addition selector over domain d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalar_selector8: E<F, D<F>>,

    /// RangeCheck0 gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub range_check0_selector8: Option<E<F, D<F>>>,

    /// RangeCheck1 gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub range_check1_selector8: Option<E<F, D<F>>>,

    /// Foreign field addition gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub foreign_field_add_selector8: Option<E<F, D<F>>>,

    /// Foreign field multiplication gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub foreign_field_mul_selector8: Option<E<F, D<F>>>,

    /// Xor gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub xor_selector8: Option<E<F, D<F>>>,

    /// Rot gate selector over domain d8
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub rot_selector8: Option<E<F, D<F>>>,
}

#[serde_as]
#[derive(Clone, Serialize, Debug)]
pub struct ConstraintSystem<F: PrimeField> {
    // Basics
    // ------
    /// number of public inputs
    pub public: usize,
    /// number of previous evaluation challenges, for recursive proving
    pub prev_challenges: usize,
    /// evaluation domains
    #[serde(bound = "EvaluationDomains<F>: Serialize + DeserializeOwned")]
    pub domain: EvaluationDomains<F>,
    /// circuit gates
    #[serde(bound = "CircuitGate<F>: Serialize + DeserializeOwned")]
    pub gates: Arc<Vec<CircuitGate<F>>>,

    pub zk_rows: u64,

    /// flags for optional features
    pub feature_flags: FeatureFlags,

    /// lazy compute mode
    lazy_mode: bool,

    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<F>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [F; PERMUTS],
    /// coefficient for the group endomorphism
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endo: F,
    /// lookup constraint system
    #[serde(bound = "LookupConstraintSystem<F>: Serialize + DeserializeOwned")]
    pub lookup_constraint_system: Arc<LazyCache<Option<LookupConstraintSystem<F>>>>,
    /// precomputes
    #[serde(skip)]
    precomputations: Arc<LazyCache<Arc<DomainConstantEvaluations<F>>>>,

    /// Disable gates checks (for testing; only enables with development builds)
    pub disable_gates_checks: bool,
}

impl<'de, F> Deserialize<'de> for ConstraintSystem<F>
where
    F: PrimeField,
    EvaluationDomains<F>: Serialize + DeserializeOwned,
    CircuitGate<F>: Serialize + DeserializeOwned,
    LookupConstraintSystem<F>: Serialize + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<ConstraintSystem<F>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[serde_as]
        #[derive(Clone, Serialize, Deserialize, Debug)]
        struct ConstraintSystemSerde<F: PrimeField> {
            public: usize,
            prev_challenges: usize,
            #[serde(bound = "EvaluationDomains<F>: Serialize + DeserializeOwned")]
            domain: EvaluationDomains<F>,
            #[serde(bound = "CircuitGate<F>: Serialize + DeserializeOwned")]
            gates: Arc<Vec<CircuitGate<F>>>,
            zk_rows: u64,
            feature_flags: FeatureFlags,
            lazy_mode: bool,
            #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
            sid: Vec<F>,
            #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
            shift: [F; PERMUTS],
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            endo: F,
            #[serde(bound = "LookupConstraintSystem<F>: Serialize + DeserializeOwned")]
            lookup_constraint_system: Arc<LazyCache<Option<LookupConstraintSystem<F>>>>,
            disable_gates_checks: bool,
        }

        // This is to avoid implementing a default value for LazyCache
        let cs = ConstraintSystemSerde::<F>::deserialize(deserializer)?;

        let precomputations = Arc::new({
            LazyCache::new(move || {
                Arc::new(DomainConstantEvaluations::create(cs.domain, cs.zk_rows).unwrap())
            })
        });

        Ok(ConstraintSystem {
            public: cs.public,
            prev_challenges: cs.prev_challenges,
            domain: cs.domain,
            gates: cs.gates,
            zk_rows: cs.zk_rows,
            feature_flags: cs.feature_flags,
            lazy_mode: cs.lazy_mode,
            sid: cs.sid,
            shift: cs.shift,
            endo: cs.endo,
            lookup_constraint_system: cs.lookup_constraint_system,
            disable_gates_checks: cs.disable_gates_checks,
            precomputations,
        })
    }
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

pub struct Builder<F: PrimeField> {
    gates: Vec<CircuitGate<F>>,
    public: usize,
    prev_challenges: usize,
    lookup_tables: Vec<LookupTable<F>>,
    runtime_tables: Option<Vec<RuntimeTableCfg<F>>>,
    precomputations: Option<Arc<DomainConstantEvaluations<F>>>,
    disable_gates_checks: bool,
    max_poly_size: Option<usize>,
    lazy_mode: bool,
}

/// Create selector polynomial for a circuit gate
pub fn selector_polynomial<F: PrimeField>(
    gate_type: GateType,
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
    target_domain: &D<F>,
    disable_gates_checks: bool,
) -> E<F, D<F>> {
    if cfg!(debug_assertions) && disable_gates_checks {
        DP::<F>::zero().evaluate_over_domain_by_ref(*target_domain)
    } else {
        // Coefficient form
        let coeff = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if gate.typ == gate_type {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();

        coeff.evaluate_over_domain_by_ref(*target_domain)
    }
}

impl<F: PrimeField> ConstraintSystem<F> {
    /// Initializes the [`ConstraintSystem<F>`] on input `gates` and `fr_sponge_params`.
    /// Returns a [`Builder<F>`]
    /// It also defaults to the following values of the builder:
    /// - `public: 0`
    /// - `prev_challenges: 0`
    /// - `lookup_tables: vec![]`,
    /// - `runtime_tables: None`,
    /// - `precomputations: None`,
    /// - `disable_gates_checks: false`,
    /// - `lazy_mode: false`,
    ///
    /// How to use it:
    /// 1. Create your instance of your builder for the constraint system using `crate(gates, sponge params)`
    /// 2. Iterativelly invoke any desired number of steps: `public(), lookup(), runtime(), precomputations(), lazy_mode()`
    /// 3. Finally call the `build()` method and unwrap the `Result` to obtain your `ConstraintSystem`
    pub fn create(gates: Vec<CircuitGate<F>>) -> Builder<F> {
        Builder {
            gates,
            public: 0,
            prev_challenges: 0,
            lookup_tables: vec![],
            runtime_tables: None,
            precomputations: None,
            disable_gates_checks: false,
            max_poly_size: None,
            lazy_mode: false,
        }
    }

    pub fn precomputations(&self) -> Arc<DomainConstantEvaluations<F>> {
        self.precomputations.get().clone()
    }

    /// test helpers
    pub fn for_testing(gates: Vec<CircuitGate<F>>) -> Self {
        let public = 0;
        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        ConstraintSystem::<F>::create(gates)
            .public(public)
            .build()
            .unwrap()
    }

    pub fn fp_for_testing(gates: Vec<CircuitGate<F>>) -> Self {
        Self::for_testing(gates)
    }
}

impl<F: PrimeField, G: KimchiCurve<ScalarField = F>, OpeningProof: OpenProof<G>>
    ProverIndex<G, OpeningProof>
{
    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    ///     witness: wire assignment witness
    ///     RETURN: verification status
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS], public: &[F]) -> Result<(), GateError> {
        // pad the witness
        let pad = vec![F::zero(); self.cs.domain.d1.size() - witness[0].len()];
        let witness: [Vec<F>; COLUMNS] = array::from_fn(|i| {
            let mut w = witness[i].to_vec();
            w.extend_from_slice(&pad);
            w
        });

        // check each rows' wiring
        for (row, gate) in self.cs.gates.iter().enumerate() {
            // check if wires are connected
            for col in 0..PERMUTS {
                let wire = gate.wires[col];

                if wire.col >= PERMUTS {
                    return Err(GateError::Custom {
                        row,
                        err: format!("a wire can only be connected to the first {PERMUTS} columns"),
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
            if row < self.cs.public && gate.coeffs.first() != Some(&F::one()) {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify(row, &witness, self, public)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        Ok(())
    }
}

impl<F: PrimeField> ConstraintSystem<F> {
    /// evaluate witness polynomials over domains
    pub fn evaluate(&self, w: &[DP<F>; COLUMNS], z: &DP<F>) -> WitnessOverDomains<F> {
        // compute shifted witness polynomials and z8, all in parallel
        let (w8, z8): ([E<F, D<F>>; COLUMNS], _) = {
            let mut res = w
                .par_iter()
                .chain(rayon::iter::once(z))
                .map(|elem| elem.evaluate_over_domain_by_ref(self.domain.d8))
                .collect::<Vec<_>>();
            let z8 = res[COLUMNS].clone();
            res.truncate(COLUMNS);
            (res.try_into().unwrap(), z8)
        };

        let w4: [E<F, D<F>>; COLUMNS] = (0..COLUMNS)
            .into_par_iter()
            .map(|i| {
                E::<F, D<F>>::from_vec_and_domain(
                    (0..self.domain.d4.size)
                        .map(|j| w8[i].evals[2 * j as usize])
                        .collect(),
                    self.domain.d4,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let z4 = DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap());
        let z8_shift8 = z8.shift(8);

        let d4_next_w: [_; COLUMNS] = w4
            .par_iter()
            .map(|w4_i| w4_i.shift(4))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let d8_next_w: [_; COLUMNS] = w8
            .par_iter()
            .map(|w8_i| w8_i.shift(8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        WitnessOverDomains {
            d4: WitnessShifts {
                next: WitnessEvals {
                    w: d4_next_w,
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
                    w: d8_next_w,
                    z: z8_shift8,
                },
                this: WitnessEvals { w: w8, z: z8 },
            },
        }
    }

    pub(crate) fn evaluated_column_coefficients(&self) -> EvaluatedColumnCoefficients<F> {
        // compute permutation polynomials
        let shifts = Shifts::new(&self.domain.d1);

        let n = self.domain.d1.size();

        let mut sigmal1: [Vec<F>; PERMUTS] = array::from_fn(|_| vec![F::zero(); n]);

        for (row, gate) in self.gates.iter().enumerate() {
            for (cell, sigma) in gate.wires.iter().zip(sigmal1.iter_mut()) {
                sigma[row] = shifts.cell_to_field(cell);
            }
        }

        // Zero out the sigmas in the zk rows, to ensure that the permutation aggregation is
        // quasi-random for those rows.
        for row in n + 2 - (self.zk_rows as usize)..n - 1 {
            for sigma in sigmal1.iter_mut() {
                sigma[row] = F::zero();
            }
        }

        let sigmal1: [_; PERMUTS] = {
            let [s0, s1, s2, s3, s4, s5, s6] = sigmal1;
            [
                E::<F, D<F>>::from_vec_and_domain(s0, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s1, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s2, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s3, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s4, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s5, self.domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s6, self.domain.d1),
            ]
        };

        let permutation_coefficients: [DP<F>; PERMUTS] =
            array::from_fn(|i| sigmal1[i].clone().interpolate());

        // poseidon gate
        let poseidon_selector = E::<F, D<F>>::from_vec_and_domain(
            self.gates.iter().map(|gate| gate.ps()).collect(),
            self.domain.d1,
        )
        .interpolate();

        // double generic gate
        let generic_selector = E::<F, D<F>>::from_vec_and_domain(
            self.gates
                .iter()
                .map(|gate| {
                    if matches!(gate.typ, GateType::Generic) {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            self.domain.d1,
        )
        .interpolate();

        // coefficient polynomial
        let coefficients: [_; COLUMNS] = array::from_fn(|i| {
            let padded = self
                .gates
                .iter()
                .map(|gate| gate.coeffs.get(i).cloned().unwrap_or_else(F::zero))
                .collect();
            let eval = E::from_vec_and_domain(padded, self.domain.d1);
            eval.interpolate()
        });

        EvaluatedColumnCoefficients {
            permutation_coefficients,
            coefficients,
            generic_selector,
            poseidon_selector,
        }
    }

    pub(crate) fn column_evaluations(
        &self,
        evaluated_column_coefficients: &EvaluatedColumnCoefficients<F>,
    ) -> ColumnEvaluations<F> {
        let permutation_coefficients8 = array::from_fn(|i| {
            evaluated_column_coefficients.permutation_coefficients[i]
                .evaluate_over_domain_by_ref(self.domain.d8)
        });

        let poseidon_selector8 = evaluated_column_coefficients
            .poseidon_selector
            .evaluate_over_domain_by_ref(self.domain.d8);

        // ECC gates
        let complete_add_selector4 = selector_polynomial(
            GateType::CompleteAdd,
            &self.gates,
            &self.domain,
            &self.domain.d4,
            self.disable_gates_checks,
        );

        let mul_selector8 = selector_polynomial(
            GateType::VarBaseMul,
            &self.gates,
            &self.domain,
            &self.domain.d8,
            self.disable_gates_checks,
        );

        let emul_selector8 = selector_polynomial(
            GateType::EndoMul,
            &self.gates,
            &self.domain,
            &self.domain.d8,
            self.disable_gates_checks,
        );

        let endomul_scalar_selector8 = selector_polynomial(
            GateType::EndoMulScalar,
            &self.gates,
            &self.domain,
            &self.domain.d8,
            self.disable_gates_checks,
        );

        let generic_selector4 = evaluated_column_coefficients
            .generic_selector
            .evaluate_over_domain_by_ref(self.domain.d4);

        // RangeCheck0 constraint selector polynomials
        let range_check0_selector8 = {
            if !self.feature_flags.range_check0 {
                None
            } else {
                Some(selector_polynomial(
                    GateType::RangeCheck0,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        // RangeCheck1 constraint selector polynomials
        let range_check1_selector8 = {
            if !self.feature_flags.range_check1 {
                None
            } else {
                Some(selector_polynomial(
                    GateType::RangeCheck1,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        // Foreign field addition constraint selector polynomial
        let foreign_field_add_selector8 = {
            if !self.feature_flags.foreign_field_add {
                None
            } else {
                Some(selector_polynomial(
                    GateType::ForeignFieldAdd,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        // Foreign field multiplication constraint selector polynomial
        let foreign_field_mul_selector8 = {
            if !self.feature_flags.foreign_field_mul {
                None
            } else {
                Some(selector_polynomial(
                    GateType::ForeignFieldMul,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        let xor_selector8 = {
            if !self.feature_flags.xor {
                None
            } else {
                Some(selector_polynomial(
                    GateType::Xor16,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        let rot_selector8 = {
            if !self.feature_flags.rot {
                None
            } else {
                Some(selector_polynomial(
                    GateType::Rot64,
                    &self.gates,
                    &self.domain,
                    &self.domain.d8,
                    self.disable_gates_checks,
                ))
            }
        };

        // TODO: This doesn't need to be degree 8 but that would require some changes in expr
        let coefficients8 = array::from_fn(|i| {
            evaluated_column_coefficients.coefficients[i]
                .evaluate_over_domain_by_ref(self.domain.d8)
        });

        ColumnEvaluations {
            permutation_coefficients8,
            coefficients8,
            generic_selector4,
            poseidon_selector8,
            complete_add_selector4,
            mul_selector8,
            emul_selector8,
            endomul_scalar_selector8,
            range_check0_selector8,
            range_check1_selector8,
            foreign_field_add_selector8,
            foreign_field_mul_selector8,
            xor_selector8,
            rot_selector8,
        }
    }
}

/// The default number of chunks in a circuit is one (< 2^16 rows)
pub const NUM_CHUNKS_BY_DEFAULT: usize = 1;

/// The number of rows required for zero knowledge in circuits with one single chunk
pub const ZK_ROWS_BY_DEFAULT: u64 = 3;

/// This function computes a strict lower bound in the number of rows required
/// for zero knowledge in circuits with `num_chunks` chunks. This means that at
/// least one needs 1 more row than the result of this function to achieve zero
/// knowledge.
/// Example:
///   for 1 chunk, this function returns 2, but at least 3 rows are needed
/// Note:
///   the number of zero knowledge rows is usually computed across the codebase
///   as the formula `(16 * num_chunks + 5) / 7`, which is precisely the formula
///   in this function plus one.
pub fn zk_rows_strict_lower_bound(num_chunks: usize) -> usize {
    (2 * (PERMUTS + 1) * num_chunks - 2) / PERMUTS
}

impl FeatureFlags {
    pub fn from_gates_and_lookup_features<F: PrimeField>(
        gates: &[CircuitGate<F>],
        lookup_features: LookupFeatures,
    ) -> FeatureFlags {
        let mut feature_flags = FeatureFlags {
            range_check0: false,
            range_check1: false,
            lookup_features,
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
        };

        for gate in gates {
            match gate.typ {
                GateType::RangeCheck0 => feature_flags.range_check0 = true,
                GateType::RangeCheck1 => feature_flags.range_check1 = true,
                GateType::ForeignFieldAdd => feature_flags.foreign_field_add = true,
                GateType::ForeignFieldMul => feature_flags.foreign_field_mul = true,
                GateType::Xor16 => feature_flags.xor = true,
                GateType::Rot64 => feature_flags.rot = true,
                _ => (),
            }
        }

        feature_flags
    }

    pub fn from_gates<F: PrimeField>(
        gates: &[CircuitGate<F>],
        uses_runtime_tables: bool,
    ) -> FeatureFlags {
        FeatureFlags::from_gates_and_lookup_features(
            gates,
            LookupFeatures::from_gates(gates, uses_runtime_tables),
        )
    }
}

impl<F: PrimeField> Builder<F> {
    /// Set up the number of public inputs.
    /// If not invoked, it equals `0` by default.
    pub fn public(mut self, public: usize) -> Self {
        self.public = public;
        self
    }

    /// Set up the number of previous challenges, used for recusive proving.
    /// If not invoked, it equals `0` by default.
    pub fn prev_challenges(mut self, prev_challenges: usize) -> Self {
        self.prev_challenges = prev_challenges;
        self
    }

    /// Set up the lookup tables.
    /// If not invoked, it is `vec![]` by default.
    ///
    /// **Warning:** you have to make sure that the IDs of the lookup tables,
    /// are unique and not colliding with IDs of built-in lookup tables, otherwise
    /// the error will be raised.
    ///
    /// (see [crate::circuits::lookup::tables]).
    pub fn lookup(mut self, lookup_tables: Vec<LookupTable<F>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    /// Set up the runtime tables.
    /// If not invoked, it is `None` by default.
    ///
    /// **Warning:** you have to make sure that the IDs of the runtime
    /// lookup tables, are unique, i.e. not colliding internaly (with other runtime tables),
    /// otherwise error will be raised.
    /// (see [crate::circuits::lookup::tables]).
    pub fn runtime(mut self, runtime_tables: Option<Vec<RuntimeTableCfg<F>>>) -> Self {
        self.runtime_tables = runtime_tables;
        self
    }

    /// Set up the shared precomputations.
    /// If not invoked, it is `None` by default.
    pub fn shared_precomputations(
        mut self,
        shared_precomputations: Arc<DomainConstantEvaluations<F>>,
    ) -> Self {
        self.precomputations = Some(shared_precomputations);
        self
    }

    /// Disable gates checks (for testing; only enables with development builds)
    pub fn disable_gates_checks(mut self, disable_gates_checks: bool) -> Self {
        self.disable_gates_checks = disable_gates_checks;
        self
    }

    pub fn max_poly_size(mut self, max_poly_size: Option<usize>) -> Self {
        self.max_poly_size = max_poly_size;
        self
    }

    pub fn lazy_mode(mut self, lazy_mode: bool) -> Self {
        self.lazy_mode = lazy_mode;
        self
    }

    /// Build the [ConstraintSystem] from a [Builder].
    pub fn build(self) -> Result<ConstraintSystem<F>, SetupError> {
        let mut gates = self.gates;
        let lookup_tables = self.lookup_tables.clone();
        let runtime_tables = self.runtime_tables.clone();

        //~ 1. If the circuit is less than 2 gates, abort.
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        let feature_flags = FeatureFlags::from_gates(&gates, runtime_tables.is_some());

        let lookup_domain_size = {
            // First we sum over the lookup table size
            let mut has_table_with_id_0 = false;
            let mut lookup_domain_size: usize = lookup_tables
                .iter()
                .map(|LookupTable { id, data }| {
                    // See below for the reason
                    if *id == 0_i32 {
                        has_table_with_id_0 = true
                    }
                    if data.is_empty() {
                        0
                    } else {
                        data[0].len()
                    }
                })
                .sum();
            // After that on the runtime tables
            if let Some(runtime_tables) = &runtime_tables {
                // FIXME: Check that a runtime table with ID 0 is enforced to
                // contain a zero entry row.
                for runtime_table in runtime_tables.iter() {
                    lookup_domain_size += runtime_table.len();
                }
            }
            // And we add the built-in tables, depending on the features.
            let LookupFeatures { patterns, .. } = &feature_flags.lookup_features;
            let mut gate_lookup_tables = GateLookupTables {
                xor: false,
                range_check: false,
            };
            for pattern in patterns.into_iter() {
                if let Some(gate_table) = pattern.table() {
                    gate_lookup_tables[gate_table] = true
                }
            }
            for gate_table in gate_lookup_tables.into_iter() {
                lookup_domain_size += gate_table.table_size();
            }

            // A dummy zero entry will be added if there is no table with ID
            // zero. Therefore we must count this in the size.
            if has_table_with_id_0 {
                lookup_domain_size
            } else {
                lookup_domain_size + 1
            }
        };

        //~ 1. Compute the number of zero-knowledge rows (`zk_rows`) that will be required to
        //~    achieve zero-knowledge. The following constraints apply to `zk_rows`:
        //~    * The number of chunks `c` results in an evaluation at `zeta` and `zeta * omega` in
        //~      each column for `2*c` evaluations per column, so `zk_rows >= 2*c + 1`.
        //~    * The permutation argument interacts with the `c` chunks in parallel, so it is
        //~      possible to cross-correlate between them to compromise zero knowledge. We know
        //~      that there is some `c >= 1` such that `zk_rows = 2*c + k` from the above. Thus,
        //~      attempting to find the evaluation at a new point, we find that:
        //~      * the evaluation of every witness column in the permutation contains `k` unknowns;
        //~      * the evaluations of the permutation argument aggregation has `k-1` unknowns;
        //~      * the permutation argument applies on all but `zk_rows - 3` rows;
        //~      * and thus we form the equation `zk_rows - 3 < 7 * k + (k - 1)` to ensure that we
        //~        can construct fewer equations than we have unknowns.
        //~
        //~    This simplifies to `k > (2 * c - 2) / 7`, giving `zk_rows > (16 * c - 2) / 7`.
        //~    We can derive `c` from the `max_poly_size` supported by the URS, and thus we find
        //~    `zk_rows` and `domain_size` satisfying the fixpoint
        //~
        //~    ```text
        //~    zk_rows = (16 * (domain_size / max_poly_size) + 5) / 7
        //~    domain_size = circuit_size + zk_rows
        //~    ```
        //~
        let (zk_rows, domain_size_lower_bound) = {
            // We add 1 to the lookup domain size because there is one element
            // used to close the permutation argument (the polynomial Z is of
            // degree n + 1 where n is the order of the subgroup H).
            let circuit_lower_bound = std::cmp::max(gates.len(), lookup_domain_size + 1);
            let get_domain_size_lower_bound = |zk_rows: u64| circuit_lower_bound + zk_rows as usize;

            let mut zk_rows = 3;
            let mut domain_size_lower_bound = get_domain_size_lower_bound(zk_rows);
            if let Some(max_poly_size) = self.max_poly_size {
                // Iterate to find a fixed-point where zk_rows is sufficient for the number of
                // chunks that we use, and also does not cause us to overflow the domain size.
                // NB: We use iteration here rather than hard-coding an assumption about
                // `compute_size_of_domain`s internals. In practice, this will never be executed
                // more than once.
                while {
                    let domain_size = D::<F>::compute_size_of_domain(domain_size_lower_bound)
                        .ok_or(SetupError::DomainCreation(
                            DomainCreationError::DomainSizeFailed(domain_size_lower_bound),
                        ))?;
                    let num_chunks = if domain_size < max_poly_size {
                        1
                    } else {
                        domain_size / max_poly_size
                    };
                    zk_rows = (zk_rows_strict_lower_bound(num_chunks) + 1) as u64;
                    domain_size_lower_bound = get_domain_size_lower_bound(zk_rows);
                    domain_size < domain_size_lower_bound
                } {}
            }
            (zk_rows, domain_size_lower_bound)
        };

        //~ 1. Create a domain for the circuit. That is,
        //~    compute the smallest subgroup of the field that
        //~    has order greater or equal to `n + zk_rows` elements.
        let domain = EvaluationDomains::<F>::create(domain_size_lower_bound)
            .map_err(SetupError::DomainCreation)?;

        assert!(domain.d1.size > zk_rows);

        //~ 1. Pad the circuit: add zero gates to reach the domain size.
        let d1_size = domain.d1.size();
        let mut padding = (gates.len()..d1_size)
            .map(|i| {
                CircuitGate::<F>::zero(array::from_fn(|j| Wire {
                    col: WIRES[j],
                    row: i,
                }))
            })
            .collect();
        gates.append(&mut padding);

        //~ 1. sample the `PERMUTS` shifts.
        let shifts = Shifts::new(&domain.d1);

        //
        // Lookup
        // ------
        let gates = Arc::new(gates);
        let gates_clone = Arc::clone(&gates);
        let lookup_constraint_system = LazyCache::new(move || {
            LookupConstraintSystem::create(
                &gates_clone,
                self.lookup_tables,
                self.runtime_tables,
                &domain,
                zk_rows as usize,
            )
            .unwrap()
        });
        if !self.lazy_mode {
            let _ = lookup_constraint_system.get(); // Precompute
        }

        let sid = shifts.map[0].clone();

        // TODO: remove endo as a field
        let endo = F::zero();

        let precomputations = if !self.lazy_mode {
            match self.precomputations {
                Some(t) => LazyCache::preinit(t),
                None => LazyCache::preinit(Arc::new(
                    DomainConstantEvaluations::create(domain, zk_rows).unwrap(),
                )),
            }
        } else {
            LazyCache::new(move || {
                Arc::new(DomainConstantEvaluations::create(domain, zk_rows).unwrap())
            })
        };

        let constraints = ConstraintSystem {
            domain,
            public: self.public,
            prev_challenges: self.prev_challenges,
            sid,
            gates,
            shift: shifts.shifts,
            endo,
            zk_rows,
            //fr_sponge_params: self.sponge_params,
            lookup_constraint_system: Arc::new(lookup_constraint_system),
            feature_flags,
            lazy_mode: self.lazy_mode,
            precomputations: Arc::new(precomputations),
            disable_gates_checks: self.disable_gates_checks,
        };

        Ok(constraints)
    }
}
