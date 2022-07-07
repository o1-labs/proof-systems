//! Range check gate

use std::collections::HashMap;

use crate::circuits::lookup::lookups::LookupInfo;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use array_init::array_init;
use rand::{prelude::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        constraints::ConstraintSystem,
        domains::EvaluationDomains,
        expr::{self, l0_1, Environment, LookupEnvironment, E},
        gate::{CircuitGate, GateType},
        lookup::{
            self,
            lookups::LookupsUsed,
            tables::{GateLookupTable, LookupTable},
        },
        polynomial::COLUMNS,
        wires::{GateWires, Wire},
    },
};

use super::{RangeCheck0, RangeCheck1};

/// Gate error
#[derive(Error, Debug, Clone, Copy, PartialEq)]
pub enum GateError {
    /// Invalid constraint
    #[error("Invalid circuit gate type {0:?}")]
    InvalidCircuitGateType(GateType),
    /// Invalid constraint
    #[error("Invalid {0:?} constraint")]
    InvalidConstraint(GateType),
    /// Invalid copy constraint
    #[error("Invalid {0:?} copy constraint")]
    InvalidCopyConstraint(GateType),
    /// Invalid lookup constraint - sorted evaluations
    #[error("Invalid {0:?} lookup constraint - sorted evaluations")]
    InvalidLookupConstraintSorted(GateType),
    /// Invalid lookup constraint - sorted evaluations
    #[error("Invalid {0:?} lookup constraint - aggregation polynomial")]
    InvalidLookupConstraintAggregation(GateType),
    /// Missing lookup constraint system
    #[error("Failed to get lookup constraint system for {0:?}")]
    MissingLookupConstraintSystem(GateType),
}
/// Keypair result
pub type Result<T> = std::result::Result<T, GateError>;

// Connect the pair of cells specified by the cell1 and cell2 parameters
// cell1 --> cell2 && cell2 --> cell1
//
// Note: This function assumes that the targeted cells are freshly instantiated
//       with self-connections.  If the two cells are transitively already part
//       of the same permutation then this would split it.
fn connect_cell_pair(wires: &mut [GateWires], cell1: (usize, usize), cell2: (usize, usize)) {
    let tmp = wires[cell1.0][cell1.1];
    wires[cell1.0][cell1.1] = wires[cell2.0][cell2.1];
    wires[cell2.0][cell2.1] = tmp;
}

impl<F: FftField + SquareRootField> CircuitGate<F> {
    /// Create range check gate for constraining three 88-bit values.
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_multi_range_check(start_row: usize) -> (usize, Vec<Self>) {
        let mut wires: Vec<GateWires> = (0..4).map(|i| Wire::new(start_row + i)).collect();

        // copy v0p0
        connect_cell_pair(&mut wires, (0, 1), (3, 3));

        // copy v0p1
        connect_cell_pair(&mut wires, (0, 2), (3, 4));

        // copy v1p0
        connect_cell_pair(&mut wires, (1, 1), (3, 5));

        // copy v1p1
        connect_cell_pair(&mut wires, (1, 2), (3, 6));

        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: wires[1],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::RangeCheck1,
                wires: wires[2],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: wires[3],
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create single range check gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_range_check(start_row: usize) -> (usize, Vec<Self>) {
        (
            start_row + 1,
            vec![CircuitGate {
                typ: GateType::RangeCheck0,
                wires: Wire::new(start_row),
                coeffs: vec![],
            }],
        )
    }

    /// Verify the witness against a range check (related) circuit gate
    ///
    /// The following verification checks are performed
    ///   * Constraint checks for circuit gates matching the self.typ kind
    ///     Circuit gates used by the range check gate are: RangeChange0 and RangeCheck1
    ///   * Permutation argument checks for copied cells / wiring
    ///   * Plookup checks for any lookups defined
    pub fn verify_range_check(
        &self,
        _: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<()> {
        if !circuit_gates().contains(&self.typ) {
            return Err(GateError::InvalidCircuitGateType(self.typ));
        }

        // Pad the witness to domain d1 size
        let padding_length = cs
            .domain
            .d1
            .size
            .checked_sub(witness[0].len() as u64)
            .unwrap();
        let mut witness = witness.clone();
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(padding_length as usize));
        }

        // Compute witness polynomial
        let witness_poly: [DensePolynomial<F>; COLUMNS] = array_init(|i| {
            Evaluations::<F, D<F>>::from_vec_and_domain(witness[i].clone(), cs.domain.d1)
                .interpolate()
        });

        // Compute permutation polynomial
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let z_poly = cs
            .perm_aggreg(&witness, &beta, &gamma, rng)
            .map_err(|_| GateError::InvalidCopyConstraint(self.typ))?;

        // Compute witness polynomial evaluations
        let witness_evals = cs.evaluate(&witness_poly, &z_poly);

        let mut index_evals = HashMap::new();
        index_evals.insert(
            self.typ,
            &cs.range_check_selector_polys[circuit_gate_selector_index(self.typ)].eval8,
        );

        // Set up lookup environment
        let lcs = cs
            .lookup_constraint_system
            .as_ref()
            .ok_or(GateError::MissingLookupConstraintSystem(self.typ))?;

        let lookup_env_data = set_up_lookup_env_data(
            self.typ,
            cs,
            &witness,
            &beta,
            &gamma,
            &lcs.configuration.lookup_info,
        )?;
        let lookup_env = Some(LookupEnvironment {
            aggreg: &lookup_env_data.aggreg8,
            sorted: &lookup_env_data.sorted8,
            selectors: &lcs.lookup_selectors,
            table: &lookup_env_data.joint_lookup_table_d8,
            runtime_selector: None,
            runtime_table: None,
        });

        // Set up the environment
        let env = {
            Environment {
                constants: expr::Constants {
                    alpha: F::rand(rng),
                    beta: F::rand(rng),
                    gamma: F::rand(rng),
                    joint_combiner: Some(F::rand(rng)),
                    endo_coefficient: cs.endo,
                    mds: vec![], // TODO: maybe cs.fr_sponge_params.mds.clone()
                },
                witness: &witness_evals.d8.this.w,
                coefficient: &cs.coefficients8,
                vanishes_on_last_4_rows: &cs.precomputations().vanishes_on_last_4_rows,
                z: &witness_evals.d8.this.z,
                l0_1: l0_1(cs.domain.d1),
                domain: cs.domain,
                index: index_evals,
                lookup: lookup_env,
            }
        };

        // Setup powers of alpha
        let mut alphas = Alphas::<F>::default();
        alphas.register(
            ArgumentType::Gate(self.typ),
            circuit_gate_constraint_count::<F>(self.typ),
        );

        // Get constraints for this circuit gate
        let constraints = circuit_gate_constraints(self.typ, &alphas);

        // Verify it against the environment
        if constraints
            .evaluations(&env)
            .interpolate()
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap()
            .1
            .is_zero()
        {
            Ok(())
        } else {
            Err(GateError::InvalidConstraint(self.typ))
        }
    }
}

// Data required by the lookup environment
struct LookupEnvironmentData<F: FftField> {
    // Aggregation evaluations
    aggreg8: Evaluations<F, D<F>>,
    // Sorted evaluations
    sorted8: Vec<Evaluations<F, D<F>>>,
    // Combined lookup table
    joint_lookup_table_d8: Evaluations<F, D<F>>,
}

// Helper to create the lookup environment data by setting up the joint- and table-id- combiners,
// computing the dummy lookup value, creating the combined lookup table, computing the sorted plookup
// evaluations and the plookup aggregation evaluations.
// Note: This function assumes the cs contains a lookup constraint system.
fn set_up_lookup_env_data<F: FftField>(
    gate_type: GateType,
    cs: &ConstraintSystem<F>,
    witness: &[Vec<F>; COLUMNS],
    beta: &F,
    gamma: &F,
    lookup_info: &LookupInfo,
) -> Result<LookupEnvironmentData<F>> {
    let lcs = cs
        .lookup_constraint_system
        .as_ref()
        .ok_or(GateError::MissingLookupConstraintSystem(gate_type))?;

    let rng = &mut StdRng::from_seed([1u8; 32]);

    // Set up joint-combiner and table-id-combiner
    let joint_lookup_used = matches!(lcs.configuration.lookup_used, LookupsUsed::Joint);
    let joint_combiner = if joint_lookup_used {
        F::rand(rng)
    } else {
        F::zero()
    };
    let table_id_combiner: F = if lcs.table_ids8.as_ref().is_some() {
        joint_combiner.pow([lcs.configuration.lookup_info.max_joint_size as u64])
    } else {
        // TODO: just set this to None in case multiple tables are not used
        F::zero()
    };

    // Compute the dummy lookup value as the combination of the last entry of the XOR table (so `(0, 0, 0)`).
    // Warning: This assumes that we always use the XOR table when using lookups.
    let dummy_lookup_value = lcs
        .configuration
        .dummy_lookup
        .evaluate(&joint_combiner, &table_id_combiner);

    // Compute the lookup table values as the combination of the lookup table entries.
    let joint_lookup_table_d8 = {
        let mut evals = Vec::with_capacity(cs.domain.d1.size());

        for idx in 0..(cs.domain.d1.size() * 8) {
            let table_id = match lcs.table_ids8.as_ref() {
                Some(table_ids8) => table_ids8.evals[idx],
                None =>
                // If there is no `table_ids8` in the constraint system,
                // every table ID is identically 0.
                {
                    F::zero()
                }
            };

            let combined_entry = {
                let table_row = lcs.lookup_table8.iter().map(|e| &e.evals[idx]);

                lookup::tables::combine_table_entry(
                    &joint_combiner,
                    &table_id_combiner,
                    table_row,
                    &table_id,
                )
            };
            evals.push(combined_entry);
        }

        Evaluations::from_vec_and_domain(evals, cs.domain.d8)
    };

    // Compute the sorted plookup evaluations
    // TODO: Once we switch to committing using lagrange commitments, `witness` will be consumed when we interpolate,
    //       so interpolation will have to moved below this.
    let sorted: Vec<_> = lookup::constraints::sorted(
        dummy_lookup_value,
        &joint_lookup_table_d8,
        cs.domain.d1,
        &cs.gates,
        witness,
        joint_combiner,
        table_id_combiner,
        lookup_info,
    )
    .map_err(|_| GateError::InvalidLookupConstraintSorted(gate_type))?;

    // Randomize the last `EVALS` rows in each of the sorted polynomials in order to add zero-knowledge to the protocol.
    let sorted: Vec<_> = sorted
        .into_iter()
        .map(|chunk| lookup::constraints::zk_patch(chunk, cs.domain.d1, rng))
        .collect();

    let sorted_coeffs: Vec<_> = sorted.iter().map(|e| e.clone().interpolate()).collect();
    let sorted8 = sorted_coeffs
        .iter()
        .map(|v| v.evaluate_over_domain_by_ref(cs.domain.d8))
        .collect::<Vec<_>>();

    // Compute the plookup aggregation evaluations
    let aggreg = lookup::constraints::aggregation::<_, F>(
        dummy_lookup_value,
        &joint_lookup_table_d8,
        cs.domain.d1,
        &cs.gates,
        witness,
        &joint_combiner,
        &table_id_combiner,
        *beta,
        *gamma,
        &sorted,
        rng,
        lookup_info,
    )
    .map_err(|_| GateError::InvalidLookupConstraintAggregation(gate_type))?;

    // Precompute different forms of the aggregation polynomial for later
    let aggreg_coeffs = aggreg.interpolate();
    // TODO: There's probably a clever way to expand the domain without interpolating
    let aggreg8 = aggreg_coeffs.evaluate_over_domain_by_ref(cs.domain.d8);

    Ok(LookupEnvironmentData {
        aggreg8,
        sorted8,
        joint_lookup_table_d8,
    })
}

fn circuit_gate_selector_index(typ: GateType) -> usize {
    match typ {
        GateType::RangeCheck0 => 0,
        GateType::RangeCheck1 => 1,
        _ => panic!("invalid gate type"),
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> Vec<GateType> {
    vec![GateType::RangeCheck0, GateType::RangeCheck1]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::<F>::CONSTRAINTS,
        GateType::RangeCheck1 => RangeCheck1::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::combined_constraints(alphas),
        GateType::RangeCheck1 => RangeCheck1::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    RangeCheck0::combined_constraints(alphas) + RangeCheck1::combined_constraints(alphas)
}

/// Range check CircuitGate selector polynomial
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SelectorPolynomial<F: FftField> {
    /// Coefficient form
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub coeff: DensePolynomial<F>,
    /// Evaluation form (evaluated over domain d8)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub eval8: Evaluations<F, D<F>>,
}

/// Create range check circuit gates selector polynomials
pub fn selector_polynomials<F: FftField>(
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
) -> Vec<SelectorPolynomial<F>> {
    Vec::from_iter(circuit_gates().iter().map(|gate_type| {
        // Coefficient form
        let coeff = Evaluations::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if gate.typ == *gate_type {
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

        SelectorPolynomial { coeff, eval8 }
    }))
}

/// Get the range check lookup table
pub fn lookup_table<F: FftField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            constraints::ConstraintSystem,
            gate::{CircuitGate, GateType},
            polynomial::COLUMNS,
            polynomials::{
                generic::GenericGateSpec,
                range_check::{self, GateError},
            },
            wires::Wire,
        },
        proof::ProverProof,
        prover_index::testing::new_index_for_test_with_lookups,
    };

    use ark_ec::AffineCurve;
    use ark_ff::{Field, One, Zero};
    use mina_curves::pasta::pallas;
    use o1_utils::FieldHelpers;

    use array_init::array_init;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;

    fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
        let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_multi_range_check(0);

        // Temporary workaround for lookup-table/domain-size issue
        for _ in 0..(1 << 13) {
            gates.push(CircuitGate::zero(Wire::new(next_row)));
            next_row += 1;
        }

        ConstraintSystem::create(gates, oracle::pasta::fp_kimchi::params())
            .build()
            .unwrap()
    }

    fn create_test_prover_index(
        public_size: usize,
    ) -> ProverIndex<mina_curves::pasta::vesta::Affine> {
        let (mut next_row, mut gates) = CircuitGate::<PallasField>::create_multi_range_check(0);

        // Temporary workaround for lookup-table/domain-size issue
        for _ in 0..(1 << 13) {
            gates.push(CircuitGate::zero(Wire::new(next_row)));
            next_row += 1;
        }

        new_index_for_test_with_lookups(gates, public_size, vec![range_check::lookup_table()], None)
    }

    #[test]
    fn verify_range_check0_zero_valid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 4]);

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        // gates[1] is RangeCheck0
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_one_invalid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 4]);

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );

        // gates[1] is RangeCheck0
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );
    }

    #[test]
    fn verify_range_check0_valid_witness() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "115655443433221211ffef000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "eeddcdccbbabaa99898877000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "7766565544343322121100000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        // gates[1] is RangeCheck0
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "23d406ac800d1af73040dd000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "a8fe8555371eb021469863000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "3edff808d8f533be9af500000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        // gates[1] is RangeCheck0
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "22f6b4e7ecb4488433ade7000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "e20e9d80333f2fba463ffd000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "25d28bfd6cdff91ca9bc00000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // Invalidate witness copy constraint
        witness[1][0] += PallasField::one();

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(GateError::InvalidCopyConstraint(GateType::RangeCheck0))
        );

        // Invalidate witness copy constraint
        witness[2][1] += PallasField::one();

        // gates[1] is RangeCheck0
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidCopyConstraint(GateType::RangeCheck0))
        );

        let mut witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "22cab5e27101eeafd2cbe1000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "1ab61d31f4e27fe41a318c000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "449a45cd749f1e091a3000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // Invalidate witness
        witness[8][0] = witness[0][0] + PallasField::one();

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );

        // Invalidate witness
        witness[8][1] = witness[0][1] + PallasField::one();

        // gates[1] is RangeCheck0
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );
    }

    #[test]
    fn verify_range_check0_valid_v0_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from(PallasField::from(2u64).pow([64])),
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from(42u64),
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::one(),
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_valid_v1_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::from(PallasField::from(2u64).pow([63])),
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::from(48u64),
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::one() + PallasField::one(),
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_invalid_v0_not_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from(2u64).pow([88]), // out of range
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from(2u64).pow([96]), // out of range
            PallasField::zero(),
            PallasField::zero(),
        );

        // gates[0] is RangeCheck0 and contains v0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );
    }

    #[test]
    fn verify_range_check0_invalid_v1_not_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::from(2u64).pow([88]), // out of range
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::from(2u64).pow([96]), // out of range
            PallasField::zero(),
        );

        // gates[1] is RangeCheck0 and contains v1
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck0))
        );
    }

    #[test]
    fn verify_range_check0_test_copy_constraints() {
        let cs = create_test_constraint_system();

        for row in 0..=1 {
            for col in 1..=2 {
                // Copy constraints impact v0 and v1
                let mut witness = range_check::create_multi_witness::<PallasField>(
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::zero(),
                );

                // Positive test case (gates[0] is a RangeCheck0 circuit gate)
                assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

                // Positive test case (gates[1] is a RangeCheck0 circuit gate)
                assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

                // Negative test cases by breaking a copy constraint
                assert_ne!(witness[col][row], PallasField::zero());
                witness[col][row] = PallasField::zero();
                assert_eq!(
                    cs.gates[0].verify_range_check(0, &witness, &cs),
                    Err(GateError::InvalidCopyConstraint(GateType::RangeCheck0))
                );
                assert_eq!(
                    cs.gates[1].verify_range_check(1, &witness, &cs),
                    Err(GateError::InvalidCopyConstraint(GateType::RangeCheck0))
                );
            }
        }
    }

    #[test]
    fn verify_range_check0_v0_test_lookups() {
        let cs = create_test_constraint_system();

        for i in 3..=6 {
            // Test ith lookup
            let mut witness = range_check::create_multi_witness::<PallasField>(
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::zero(),
                PallasField::zero(),
            );

            // Positive test
            // gates[0] is RangeCheck0 and constrains some of v0
            assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

            // Negative test
            // make ith plookup limb out of range
            witness[i][0] = PallasField::from(2u64.pow(12));

            // gates[0] is RangeCheck0 and constrains some of v0
            assert_eq!(
                cs.gates[0].verify_range_check(0, &witness, &cs),
                Err(GateError::InvalidLookupConstraintSorted(
                    GateType::RangeCheck0
                ))
            );
        }
    }

    #[test]
    fn verify_range_check0_v1_test_lookups() {
        let cs = create_test_constraint_system();

        for i in 3..=6 {
            // Test ith lookup
            let mut witness = range_check::create_multi_witness::<PallasField>(
                PallasField::zero(),
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                PallasField::zero(),
            );

            // Positive test
            // gates[1] is RangeCheck0 and constrains some of v1
            assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

            // Negative test
            // make ith plookup limb out of range
            witness[i][1] = PallasField::from(2u64.pow(12));

            // gates[1] is RangeCheck0 and constrains some of v1
            assert_eq!(
                cs.gates[1].verify_range_check(1, &witness, &cs),
                Err(GateError::InvalidLookupConstraintSorted(
                    GateType::RangeCheck0
                ))
            );
        }
    }

    #[test]
    fn verify_range_check1_zero_valid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 4]);

        // gates[2] is RangeCheck1
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check1_one_invalid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 4]);

        // gates[2] is RangeCheck1
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck1))
        );
    }

    #[test]
    fn verify_range_check1_valid_witness() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "22cab5e27101eeafd2cbe1000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "1ab61d31f4e27fe41a318c000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "449a45cd749f1e091a3000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // gates[2] is RangeCheck1
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "0d96f6fc210316c73bcc4d000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "59c8e7b0ffb3cab6ce8d48000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "686c10e73930b92f375800000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // gates[2] is RangeCheck1
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check1_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "2ce2d3ac942f98d59e7e11000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "52dd43524b95399f5d458d000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "60ca087b427918fa0e2600000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // Corrupt witness
        witness[0][2] = witness[7][2];

        // gates[2] is RangeCheck1
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck1))
        );

        let mut witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "1bd50c94d2dc83d32f01c0000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "e983d7cd9e28e440930f86000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "ea226054772cd009d2af00000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // Corrupt witness
        witness[13][2] = witness[3][2];

        // gates[2] is RangeCheck1
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck1))
        );
    }

    #[test]
    fn verify_range_check1_valid_v2_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(PallasField::from(2u64).pow([88]) - PallasField::one()),
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(PallasField::from(2u64).pow([64])),
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(42u64),
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::one(),
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check1_invalid_v2_not_in_range() {
        let cs = create_test_constraint_system();

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(2u64).pow([88]), // out of range
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck1))
        );

        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::zero(),
            PallasField::zero(),
            PallasField::from(2u64).pow([96]), // out of range
        );

        // gates[2] is RangeCheck1 and constrains v2
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(GateError::InvalidConstraint(GateType::RangeCheck1))
        );
    }

    #[test]
    fn verify_range_check1_test_copy_constraints() {
        let cs = create_test_constraint_system();

        for row in 0..=1 {
            for col in 1..=2 {
                // Copy constraints impact v0 and v1
                let mut witness = range_check::create_multi_witness::<PallasField>(
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::zero(),
                );

                // Positive test case (gates[2] is a RangeCheck1 circuit gate)
                assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

                // Negative test case by breaking a copy constraint
                assert_ne!(witness[col][row], PallasField::zero());
                witness[col][row] = PallasField::zero();
                assert_eq!(
                    cs.gates[2].verify_range_check(2, &witness, &cs),
                    Err(GateError::InvalidCopyConstraint(GateType::RangeCheck1))
                );
            }
        }
    }

    #[test]
    fn verify_range_check1_test_curr_row_lookups() {
        let cs = create_test_constraint_system();

        for i in 3..=6 {
            // Test ith lookup (impacts v2)
            let mut witness = range_check::create_multi_witness::<PallasField>(
                PallasField::zero(),
                PallasField::zero(),
                PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
            );

            // Positive test
            // gates[2] is RangeCheck1 and constrains v2
            assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

            // Negative test
            // make ith plookup limb out of range
            witness[i][2] = PallasField::from(2u64.pow(12));

            // gates[2] is RangeCheck1 and constrains v2
            assert_eq!(
                cs.gates[2].verify_range_check(2, &witness, &cs),
                Err(GateError::InvalidLookupConstraintSorted(
                    GateType::RangeCheck1
                ))
            );
        }
    }

    #[test]
    fn verify_range_check1_test_next_row_lookups() {
        // TODO
        let cs = create_test_constraint_system();

        for row in 0..=1 {
            for col in 1..=2 {
                let mut witness = range_check::create_multi_witness::<PallasField>(
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::from(2u64).pow([88]) - PallasField::one(), // in range
                    PallasField::zero(),
                );

                // Positive test case (gates[2] is RangeCheck1 and constrains
                // both v0's and v1's lookups that are deferred to 4th row)
                assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

                // Negative test by making plookup limb out of range
                // and making sure copy constraint is valid
                witness[col][row] = PallasField::from(2u64.pow(12));
                witness[col - 1 + 2 * row + 3][3] = PallasField::from(2u64.pow(12));
                assert_eq!(
                    cs.gates[2].verify_range_check(2, &witness, &cs),
                    Err(GateError::InvalidLookupConstraintSorted(
                        GateType::RangeCheck1
                    ))
                );
            }
        }
    }

    #[test]
    fn verify_64_bit_range_check() {
        // Test circuit layout
        //    Row Gate        Cells       Description
        //      0 GenericPub  0 <-,-, ... Used to get a cell with zero
        //      1 RangeCheck0 v0  0 0 ... Wire cells 1 and 2 to 1st cell 0 of GenericPub
        let mut gates = vec![];
        gates.push(CircuitGate::<PallasField>::create_generic_gadget(
            Wire::new(0),
            GenericGateSpec::Pub,
            None,
        ));
        gates.append(&mut CircuitGate::<PallasField>::create_range_check(1).1);
        gates[1].wires[1] = Wire { row: 1, col: 2 };
        gates[1].wires[2] = Wire { row: 0, col: 0 };
        gates[0].wires[0] = Wire { row: 1, col: 1 };

        // Temporary workaround for lookup-table/domain-size issue
        let mut next_row = 2;
        for _ in 0..(1 << 13) {
            gates.push(CircuitGate::zero(Wire::new(next_row)));
            next_row += 1;
        }

        // Create constraint system
        let cs = ConstraintSystem::create(gates, oracle::pasta::fp_kimchi::params())
            .build()
            .unwrap();

        // Witness layout (positive test case)
        //   Row 0 1 2 3 ... 14  Gate
        //   0   0 0 0 0 ... 0   GenericPub
        //   1   0 0 X X ... X   RangeCheck0
        let mut witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::zero()]);
        range_check::create_witness::<PallasField>(
            PallasField::from(2u64).pow([64]) - PallasField::one(), // in range
        )
        .iter_mut()
        .enumerate()
        .for_each(|(row, col)| witness[row].append(col));

        // Positive test case
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        // Witness layout (negative test case)
        //   Row 0 1 2 3 ... 14  Gate
        //   0   0 0 0 0 ... 0   GenericPub
        //   1   0 X X X ... X   RangeCheck0
        let mut witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::zero()]);
        range_check::create_witness::<PallasField>(
            PallasField::from(2u64).pow([64]), // out of range
        )
        .iter_mut()
        .enumerate()
        .for_each(|(row, col)| witness[row].append(col));

        // Negative test case
        assert_eq!(
            cs.gates[1].verify_range_check(1, &witness, &cs),
            Err(GateError::InvalidCopyConstraint(GateType::RangeCheck0))
        );
    }

    use crate::{prover_index::ProverIndex, verifier::verify};
    use commitment_dlog::commitment::CommitmentCurve;
    use groupmap::GroupMap;
    use mina_curves::pasta as pasta_curves;
    use oracle::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };

    type BaseSponge<'a> =
        DefaultFqSponge<'a, pasta_curves::vesta::VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge<'a> = DefaultFrSponge<'a, pasta_curves::Fp, PlonkSpongeConstantsKimchi>;

    #[test]
    fn verify_range_check_valid_proof1() {
        // Create prover index
        let prover_index = create_test_prover_index(0);

        // Create witness
        let witness = range_check::create_multi_witness::<PallasField>(
            PallasField::from_hex(
                "2bc0afaa2f6f50b1d1424b000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "8b30889f3a39e297ac851a000000000000000000000000000000000000000000",
            )
            .unwrap(),
            PallasField::from_hex(
                "c1c85ec47635e8edac5600000000000000000000000000000000000000000000",
            )
            .unwrap(),
        );

        // Verify computed witness satisfies the circuit
        prover_index.cs.verify(&witness, &[]).unwrap();

        // Generate proof
        let group_map = <pasta_curves::vesta::Affine as CommitmentCurve>::Map::setup();
        let proof = ProverProof::create::<BaseSponge, ScalarSponge>(
            &group_map,
            witness,
            &[],
            &prover_index,
        )
        .expect("failed to generate proof");

        // Get the verifier index
        let verifier_index = prover_index.verifier_index();

        // Verify proof
        let res = verify::<pasta_curves::vesta::Affine, BaseSponge, ScalarSponge>(
            &group_map,
            &verifier_index,
            &proof,
        );

        assert!(!res.is_err());
    }
}
