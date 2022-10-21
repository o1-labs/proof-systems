//! This module implements Plonk circuit constraint primitive.
use super::{gate::SelectorPolynomial, lookup::runtime_tables::RuntimeTableCfg};
use crate::{
    circuits::{
        domain_constant_evaluation::DomainConstantEvaluations,
        domains::EvaluationDomains,
        gate::{CircuitGate, GateType},
        lookup::{index::LookupConstraintSystem, tables::LookupTable},
        polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
        polynomials::permutation::{Shifts, ZK_ROWS},
        polynomials::{foreign_field_add, range_check},
        wires::*,
    },
    curve::KimchiCurve,
    error::SetupError,
};
use ark_ff::{PrimeField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use num_bigint::BigUint;
use o1_utils::{ExtendedEvaluations, FieldHelpers};
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::array;
use std::{collections::HashSet, sync::Arc};

//
// ConstraintSystem
//

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

    // Polynomials over the monomial base
    // ----------------------------------
    /// permutation polynomial array
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmam: [DP<F>; PERMUTS],

    // Coefficient polynomials. These define constant that gates can use as they like.
    // ---------------------------------------
    /// coefficients polynomials in evaluation form
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficients8: [E<F, D<F>>; COLUMNS],

    // Generic constraint selector polynomials
    // ---------------------------------------
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub genericm: DP<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub psm: DP<F>,

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// multiplication evaluations over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic4: E<F, D<F>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal1: [E<F, D<F>>; PERMUTS],
    /// permutation polynomial array evaluations over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal8: [E<F, D<F>>; PERMUTS],
    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon selector over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ps8: E<F, D<F>>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition selector evaluations w over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub complete_addl4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mull8: E<F, D<F>>,
    /// endoscalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emull: E<F, D<F>>,
    /// ChaCha indexes
    #[serde_as(as = "Option<[o1_utils::serialization::SerdeAs; 4]>")]
    pub chacha8: Option<[E<F, D<F>>; 4]>,
    /// EC point addition selector evaluations w over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalar8: E<F, D<F>>,

    /// Range check gate selector polynomials
    #[serde(
        bound = "[SelectorPolynomial<F>; range_check::gadget::GATE_COUNT]: Serialize + DeserializeOwned"
    )]
    pub range_check_selector_polys:
        Option<[SelectorPolynomial<F>; range_check::gadget::GATE_COUNT]>,

    /// Foreign field modulus
    pub foreign_field_modulus: Option<BigUint>,

    /// Foreign field addition gate selector polynomial
    #[serde(bound = "Option<SelectorPolynomial<F>>: Serialize + DeserializeOwned")]
    pub foreign_field_add_selector_poly: Option<SelectorPolynomial<F>>,

    /// Keccak rotation table
    #[serde_as(as = "Option<[[o1_utils::serialization::SerdeAs; 5]; 5]>")]
    pub keccak_rotation_table: Option<[[F; 5]; 5]>,

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
    keccak_rotation_table: Option<[[F; 5]; 5]>,
}

/// Create selector polynomial for a circuit gate
pub fn selector_polynomial<F: PrimeField>(
    gate_type: GateType,
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
) -> SelectorPolynomial<F> {
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

    // Evaluation form (evaluated over d8)
    let eval8 = coeff.evaluate_over_domain_by_ref(domain.d8);

    SelectorPolynomial { eval8 }
}

/// Create selector polynomials for a gate (i.e. a collection of circuit gates)
pub fn selector_polynomials<F: PrimeField>(
    gate_types: &[GateType],
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
) -> Vec<SelectorPolynomial<F>> {
    Vec::from_iter(
        gate_types
            .iter()
            .map(|gate_type| selector_polynomial(*gate_type, gates, domain)),
    )
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
            keccak_rotation_table: None,
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

    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    ///     witness: wire assignment witness
    ///     RETURN: verification status
    pub fn verify<G: KimchiCurve<ScalarField = F>>(
        &self,
        witness: &[Vec<F>; COLUMNS],
        public: &[F],
    ) -> Result<(), GateError> {
        // pad the witness
        let pad = vec![F::zero(); self.domain.d1.size() - witness[0].len()];
        let witness: [Vec<F>; COLUMNS] = array::from_fn(|i| {
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
            if row < self.public && gate.coeffs[0] != F::one() {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify::<G>(row, &witness, self, public)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        Ok(())
    }

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
        if let Some(ffmod) = foreign_field_modulus.clone() {
            if ffmod <= F::modulus_biguint() {
                println!("Smaller foreign field modulus is still only supported by FFAdd but not yet for FFMul");
            }
        }
        self.foreign_field_modulus = foreign_field_modulus.clone();
        self
    }

    /// Creates the 5x5 table of rotation bits for Keccak modulo 64
    /// | y \ x |  0 |  1 |  2 |  3 |  4 |
    /// | ----- | -- | -- | -- | -- | -- |
    /// | 0     |  0 |  1 | 62 | 28 | 27 |
    /// | 1     | 36 | 44 |  6 | 55 | 20 |
    /// | 2     |  3 | 10 | 43 | 25 | 39 |
    /// | 3     | 41 | 45 | 15 | 21 |  8 |
    /// | 4     | 18 |  2 | 61 | 56 | 14 |
    // TODO: NOT SURE YET IF WILL BE USEFUL HERE OR NOT
    pub fn keccak_rotation_table(mut self) -> Self {
        self.keccak_rotation_table = Some([
            [
                F::zero(),
                F::from(36u32),
                F::from(3u32),
                F::from(41u32),
                F::from(18u32),
            ],
            [
                F::one(),
                F::from(44u32),
                F::from(10u32),
                F::from(45u32),
                F::from(2u32),
            ],
            [
                F::from(60u32),
                F::from(6u32),
                F::from(43u32),
                F::from(15u32),
                F::from(61u32),
            ],
            [
                F::from(28u32),
                F::from(55u32),
                F::from(25u32),
                F::from(21u32),
                F::from(56u32),
            ],
            [
                F::from(27u32),
                F::from(20u32),
                F::from(39u32),
                F::from(8u32),
                F::from(14u32),
            ],
        ]);
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
        let mut sigmal1: [Vec<F>; PERMUTS] = array::from_fn(|_| vec![F::zero(); domain.d1.size()]);

        for (row, gate) in gates.iter().enumerate() {
            for (cell, sigma) in gate.wires.iter().zip(sigmal1.iter_mut()) {
                sigma[row] = shifts.cell_to_field(cell);
            }
        }

        let sigmal1: [_; PERMUTS] = {
            let [s0, s1, s2, s3, s4, s5, s6] = sigmal1;
            [
                E::<F, D<F>>::from_vec_and_domain(s0, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s1, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s2, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s3, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s4, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s5, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s6, domain.d1),
            ]
        };

        let sigmam: [DP<F>; PERMUTS] = array::from_fn(|i| sigmal1[i].clone().interpolate());

        let sigmal8 = array::from_fn(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8));

        // Gates
        // -----
        //
        // Compute each gate's polynomial as
        // the polynomial that evaluates to 1 at $g^i$
        // where $i$ is the row where a gate is active.
        // Note: gates must be mutually exclusive.

        // poseidon gate
        let psm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.ps()).collect(),
            domain.d1,
        )
        .interpolate();
        let ps8 = psm.evaluate_over_domain_by_ref(domain.d8);

        // ECC gates
        let complete_addm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::CompleteAdd) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let complete_addl4 = complete_addm.evaluate_over_domain_by_ref(domain.d4);

        let mulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.vbmul()).collect(),
            domain.d1,
        )
        .interpolate();
        let mull8 = mulm.evaluate_over_domain_by_ref(domain.d8);

        let emulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.endomul()).collect(),
            domain.d1,
        )
        .interpolate();
        let emull = emulm.evaluate_over_domain_by_ref(domain.d8);

        let endomul_scalarm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::EndoMulScalar) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let endomul_scalar8 = endomul_scalarm.evaluate_over_domain_by_ref(domain.d8);

        // double generic gate
        let genericm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if matches!(gate.typ, GateType::Generic) {
                        F::one()
                    } else {
                        F::zero()
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
                let a: [_; 4] = array::from_fn(|i| {
                    let g = match i {
                        0 => ChaCha0,
                        1 => ChaCha1,
                        2 => ChaCha2,
                        3 => ChaChaFinal,
                        _ => panic!("Invalid index"),
                    };
                    E::<F, D<F>>::from_vec_and_domain(
                        gates
                            .iter()
                            .map(|gate| if gate.typ == g { F::one() } else { F::zero() })
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
        let range_gates = range_check::gadget::circuit_gates();
        let range_check_selector_polys = {
            if circuit_gates_used.is_disjoint(&range_gates.into_iter().collect()) {
                None
            } else {
                Some(array::from_fn(|i| {
                    selector_polynomial(range_gates[i], &gates, &domain)
                }))
            }
        };

        // Foreign field addition constraint selector polynomial
        let ffadd_gates = foreign_field_add::gadget::circuit_gates();
        let foreign_field_add_selector_poly = {
            if circuit_gates_used.is_disjoint(&ffadd_gates.into_iter().collect()) {
                None
            } else {
                Some(selector_polynomial(ffadd_gates[0], &gates, &domain))
            }
        };

        //
        // Coefficient
        // -----------
        //

        // coefficient polynomial
        let coefficientsm: [_; COLUMNS] = array::from_fn(|i| {
            let padded = gates
                .iter()
                .map(|gate| gate.coeffs.get(i).cloned().unwrap_or_else(F::zero))
                .collect();
            let eval = E::from_vec_and_domain(padded, domain.d1);
            eval.interpolate()
        });
        // TODO: This doesn't need to be degree 8 but that would require some changes in expr
        let coefficients8 =
            array::from_fn(|i| coefficientsm[i].evaluate_over_domain_by_ref(domain.d8));

        //
        // Lookup
        // ------
        let lookup_constraint_system =
            LookupConstraintSystem::create(&gates, lookup_tables, runtime_tables, &domain)
                .map_err(|e| SetupError::ConstraintSystem(e.to_string()))?;

        let sid = shifts.map[0].clone();

        // TODO: remove endo as a field
        let endo = F::zero();

        let domain_constant_evaluation = OnceCell::new();

        let constraints = ConstraintSystem {
            chacha8,
            endomul_scalar8,
            domain,
            public: self.public,
            prev_challenges: self.prev_challenges,
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
            foreign_field_add_selector_poly,
            foreign_field_modulus: self.foreign_field_modulus,
            keccak_rotation_table: self.keccak_rotation_table,
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
            //let fp_sponge_params = oracle::pasta::fp_kimchi::params();
            Self::for_testing(gates)
        }
    }
}
