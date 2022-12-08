//! This module implements Plonk circuit constraint primitive.
use super::lookup::runtime_tables::RuntimeTableCfg;
use crate::{
    circuits::{
        domain_constant_evaluation::DomainConstantEvaluations,
        domains::EvaluationDomains,
        gate::{CircuitGate, GateType},
        lookup::{
            constraints::LookupConfiguration, index::LookupConstraintSystem, tables::LookupTable,
        },
        polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
        polynomials::permutation::{Shifts, ZK_ROWS},
        polynomials::range_check,
        wires::*,
    },
    curve::KimchiCurve,
    error::SetupError,
    prover_index::ProverIndex,
};
use ark_ff::{PrimeField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use num_bigint::BigUint;
use o1_utils::ExtendedEvaluations;
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::array;
use std::sync::Arc;

//
// ConstraintSystem
//

/// Flags for optional features in the constraint system
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "F: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize")]
pub struct FeatureFlags<F> {
    /// ChaCha gates
    pub chacha: bool,
    /// Range check gates
    pub range_check: bool,
    /// Foreign field addition gate
    pub foreign_field_add: bool,
    /// Foreign field multiplication gate
    pub foreign_field_mul: bool,
    /// XOR gate
    pub xor: bool,
    /// ROT gate
    pub rot: bool,
    /// Lookups
    pub lookup_configuration: Option<LookupConfiguration<F>>,
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

    /// ChaCha selectors over domain d8
    #[serde_as(as = "Option<[o1_utils::serialization::SerdeAs; 4]>")]
    pub chacha_selectors8: Option<[E<F, D<F>>; 4]>,

    /// EC point addition selector over domain d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalar_selector8: E<F, D<F>>,

    /// Range check gate selector over domain d8
    #[serde_as(as = "Option<[o1_utils::serialization::SerdeAs; range_check::gadget::GATE_COUNT]>")]
    pub range_check_selectors8: Option<[E<F, D<F>>; range_check::gadget::GATE_COUNT]>,

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
#[derive(Clone, Serialize, Deserialize, Debug)]
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
    pub gates: Vec<CircuitGate<F>>,

    /// flags for optional features
    #[serde(bound = "FeatureFlags<F>: Serialize + DeserializeOwned")]
    pub feature_flags: FeatureFlags<F>,

    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<F>,

    /// Foreign field modulus
    pub foreign_field_modulus: Option<BigUint>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [F; PERMUTS],
    /// coefficient for the group endomorphism
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endo: F,
    /// lookup constraint system
    #[serde(bound = "LookupConstraintSystem<F>: Serialize + DeserializeOwned")]
    pub lookup_constraint_system: Option<LookupConstraintSystem<F>>,
    /// precomputes
    #[serde(skip)]
    precomputations: OnceCell<Arc<DomainConstantEvaluations<F>>>,
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
    foreign_field_modulus: Option<BigUint>,
}

/// Create selector polynomial for a circuit gate
pub fn selector_polynomial<F: PrimeField>(
    gate_type: GateType,
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
    target_domain: &D<F>,
) -> E<F, D<F>> {
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

impl<F: PrimeField> ConstraintSystem<F> {
    /// Initializes the [ConstraintSystem<F>] on input `gates` and `fr_sponge_params`.
    /// Returns a [Builder<F>]
    /// It also defaults to the following values of the builder:
    /// - `public: 0`
    /// - `prev_challenges: 0`
    /// - `lookup_tables: vec![]`,
    /// - `runtime_tables: None`,
    /// - `precomputations: None`,
    ///
    /// How to use it:
    /// 1. Create your instance of your builder for the constraint system using `crate(gates, sponge params)`
    /// 2. Iterativelly invoke any desired number of steps: `public(), lookup(), runtime(), precomputations()``
    /// 3. Finally call the `build()` method and unwrap the `Result` to obtain your `ConstraintSystem`
    pub fn create(gates: Vec<CircuitGate<F>>) -> Builder<F> {
        Builder {
            gates,
            public: 0,
            prev_challenges: 0,
            lookup_tables: vec![],
            runtime_tables: None,
            precomputations: None,
            foreign_field_modulus: None,
        }
    }

    pub fn precomputations(&self) -> &Arc<DomainConstantEvaluations<F>> {
        self.precomputations
            .get_or_init(|| Arc::new(DomainConstantEvaluations::create(self.domain).unwrap()))
    }

    pub fn set_precomputations(&self, precomputations: Arc<DomainConstantEvaluations<F>>) {
        self.precomputations
            .set(precomputations)
            .expect("Precomputation has been set before");
    }
}

impl<F: PrimeField + SquareRootField, G: KimchiCurve<ScalarField = F>> ProverIndex<G> {
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
            if row < self.cs.public && gate.coeffs[0] != F::one() {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify::<G>(row, &witness, self, public)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        Ok(())
    }
}

impl<F: PrimeField + SquareRootField> ConstraintSystem<F> {
    /// evaluate witness polynomials over domains
    pub fn evaluate(&self, w: &[DP<F>; COLUMNS], z: &DP<F>) -> WitnessOverDomains<F> {
        // compute shifted witness polynomials
        let w8: [E<F, D<F>>; COLUMNS] =
            array::from_fn(|i| w[i].evaluate_over_domain_by_ref(self.domain.d8));
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        let w4: [E<F, D<F>>; COLUMNS] = array::from_fn(|i| {
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
                    w: array::from_fn(|i| w4[i].shift(4)),
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
                    w: array::from_fn(|i| w8[i].shift(8)),
                    z: z8.shift(8),
                },
                this: WitnessEvals { w: w8, z: z8 },
            },
        }
    }

    pub(crate) fn evaluated_column_coefficients(&self) -> EvaluatedColumnCoefficients<F> {
        // compute permutation polynomials
        let shifts = Shifts::new(&self.domain.d1);

        let mut sigmal1: [Vec<F>; PERMUTS] =
            array::from_fn(|_| vec![F::zero(); self.domain.d1.size()]);

        for (row, gate) in self.gates.iter().enumerate() {
            for (cell, sigma) in gate.wires.iter().zip(sigmal1.iter_mut()) {
                sigma[row] = shifts.cell_to_field(cell);
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
        );

        let mul_selector8 = selector_polynomial(
            GateType::VarBaseMul,
            &self.gates,
            &self.domain,
            &self.domain.d8,
        );

        let emul_selector8 = selector_polynomial(
            GateType::EndoMul,
            &self.gates,
            &self.domain,
            &self.domain.d8,
        );

        let endomul_scalar_selector8 = selector_polynomial(
            GateType::EndoMulScalar,
            &self.gates,
            &self.domain,
            &self.domain.d8,
        );

        let generic_selector4 = evaluated_column_coefficients
            .generic_selector
            .evaluate_over_domain_by_ref(self.domain.d4);

        // chacha gate
        let chacha_selectors8 = {
            if !self.feature_flags.chacha {
                None
            } else {
                Some([
                    selector_polynomial(
                        GateType::ChaCha0,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                    selector_polynomial(
                        GateType::ChaCha1,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                    selector_polynomial(
                        GateType::ChaCha2,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                    selector_polynomial(
                        GateType::ChaChaFinal,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                ])
            }
        };

        // Range check constraint selector polynomials
        let range_check_selectors8 = {
            if !self.feature_flags.range_check {
                None
            } else {
                Some([
                    selector_polynomial(
                        GateType::RangeCheck0,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                    selector_polynomial(
                        GateType::RangeCheck1,
                        &self.gates,
                        &self.domain,
                        &self.domain.d8,
                    ),
                ])
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
            chacha_selectors8,
            endomul_scalar_selector8,
            range_check_selectors8,
            foreign_field_add_selector8,
            foreign_field_mul_selector8,
            xor_selector8,
            rot_selector8,
        }
    }
}

impl<F: PrimeField + SquareRootField> Builder<F> {
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
    /// are unique and  not colliding with IDs of built-in lookup tables
    /// (see [crate::circuits::lookup::tables]).
    pub fn lookup(mut self, lookup_tables: Vec<LookupTable<F>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    /// Set up the runtime tables.
    /// If not invoked, it is `None` by default.
    ///
    /// **Warning:** you have to make sure that the IDs of the runtime lookup tables,
    /// are unique and not colliding with IDs of built-in lookup tables
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

    /// Set up the foreign field modulus passed as an optional BigUint
    /// If not invoked, it is `None` by default.
    /// Panics if the BigUint being passed needs more than 3 limbs of 88 bits each
    /// and warns if the foreign modulus being passed is smaller than the native modulus
    /// because right now we only support foreign modulus that are larger than the native modulus.
    pub fn foreign_field_modulus(mut self, foreign_field_modulus: &Option<BigUint>) -> Self {
        self.foreign_field_modulus = foreign_field_modulus.clone();
        self
    }

    /// Build the [ConstraintSystem] from a [Builder].
    pub fn build(self) -> Result<ConstraintSystem<F>, SetupError> {
        let mut gates = self.gates;
        let lookup_tables = self.lookup_tables;
        let runtime_tables = self.runtime_tables;

        //~ 1. If the circuit is less than 2 gates, abort.
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        //~ 2. Create a domain for the circuit. That is,
        //~    compute the smallest subgroup of the field that
        //~    has order greater or equal to `n + ZK_ROWS` elements.
        let domain = EvaluationDomains::<F>::create(gates.len() + ZK_ROWS as usize)?;

        assert!(domain.d1.size > ZK_ROWS);

        //~ 3. Pad the circuit: add zero gates to reach the domain size.
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

        let mut feature_flags = FeatureFlags {
            chacha: false,
            range_check: false,
            lookup_configuration: None,
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
        };

        for gate in &gates {
            match gate.typ {
                GateType::ChaCha0
                | GateType::ChaCha1
                | GateType::ChaCha2
                | GateType::ChaChaFinal => feature_flags.chacha = true,
                GateType::RangeCheck0 | GateType::RangeCheck1 => feature_flags.range_check = true,
                GateType::ForeignFieldAdd => feature_flags.foreign_field_add = true,
                GateType::ForeignFieldMul => feature_flags.foreign_field_mul = true,
                GateType::Xor16 => feature_flags.xor = true,
                GateType::Rot64 => feature_flags.rot = true,
                _ => (),
            }
        }

        //~ 4. sample the `PERMUTS` shifts.
        let shifts = Shifts::new(&domain.d1);

        //
        // Lookup
        // ------
        let lookup_constraint_system =
            LookupConstraintSystem::create(&gates, lookup_tables, runtime_tables, &domain)
                .map_err(|e| SetupError::ConstraintSystem(e.to_string()))?;
        feature_flags.lookup_configuration = lookup_constraint_system
            .as_ref()
            .map(|lcs| lcs.configuration.clone());

        let sid = shifts.map[0].clone();

        // TODO: remove endo as a field
        let endo = F::zero();

        let domain_constant_evaluation = OnceCell::new();

        let constraints = ConstraintSystem {
            domain,
            public: self.public,
            prev_challenges: self.prev_challenges,
            sid,
            foreign_field_modulus: self.foreign_field_modulus,
            gates,
            shift: shifts.shifts,
            endo,
            //fr_sponge_params: self.sponge_params,
            lookup_constraint_system,
            feature_flags,
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
    use mina_curves::pasta::Fp;

    impl<F: PrimeField + SquareRootField> ConstraintSystem<F> {
        pub fn for_testing(gates: Vec<CircuitGate<F>>) -> Self {
            let public = 0;
            // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
            ConstraintSystem::<F>::create(gates)
                .public(public)
                .build()
                .unwrap()
        }
    }

    impl ConstraintSystem<Fp> {
        pub fn fp_for_testing(gates: Vec<CircuitGate<Fp>>) -> Self {
            //let fp_sponge_params = mina_poseidon::pasta::fp_kimchi::params();
            Self::for_testing(gates)
        }
    }
}
