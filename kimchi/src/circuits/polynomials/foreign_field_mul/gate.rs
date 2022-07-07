use std::collections::HashMap;

use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use array_init::array_init;
use rand::{prelude::StdRng, SeedableRng};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        constraints::ConstraintSystem,
        expr::{self, l0_1, Environment, LookupEnvironment, E},
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, GateType},
        lookup::{
            self,
            lookups::{LookupInfo, LookupsUsed},
        },
        polynomial::COLUMNS,
        wires::{GateWires, Wire},
    },
};

use super::ForeignFieldMul;

impl<F: FftField + SquareRootField> CircuitGate<F> {
    /// Create foreign field multiplication gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_foreign_field_mul(start_row: usize) -> (usize, Vec<Self>) {
        // Create multi-range-check gates for $a, b, q, r, p_{10}, p_{111}$ and $v_{10}$
        let mut circuit_gates = vec![];
        let mut next_row = start_row;
        for _ in 0..5 {
            let (subsequent_row, mut range_check_circuit_gates) =
                CircuitGate::create_multi_range_check(next_row);
            circuit_gates.append(&mut range_check_circuit_gates);
            next_row = subsequent_row
        }

        // Foreign field multiplication gates
        let mut wires: Vec<GateWires> = (0..2).map(|i| Wire::new(next_row + i)).collect();

        // Copy left_input0 -> Curr(0)
        connect_cell_pair(&mut circuit_gates[0].wires, 0, &mut wires, (0, 0));
        // Copy left_input1 -> Curr(1)
        connect_cell_pair(&mut circuit_gates[1].wires, 0, &mut wires, (0, 1));
        // Copy left_input2 -> Curr(2)
        connect_cell_pair(&mut circuit_gates[2].wires, 0, &mut wires, (0, 2));
        // Copy right_input0 -> Curr(3)
        connect_cell_pair(&mut circuit_gates[4].wires, 0, &mut wires, (0, 3));
        // Copy right_input1 -> Curr(4)
        connect_cell_pair(&mut circuit_gates[5].wires, 0, &mut wires, (0, 4));
        // Copy right_input2 -> Curr(5)
        connect_cell_pair(&mut circuit_gates[6].wires, 0, &mut wires, (0, 5));
        // Copy quotient0 -> Curr(6)
        connect_cell_pair(&mut circuit_gates[8].wires, 0, &mut wires, (0, 6));

        // Copy quotient1 -> Next(0)
        connect_cell_pair(&mut circuit_gates[9].wires, 0, &mut wires, (1, 0));
        // Copy quotient2 -> Next(1)
        connect_cell_pair(&mut circuit_gates[10].wires, 0, &mut wires, (1, 1));
        // Copy remainder0 -> Next(4)
        connect_cell_pair(&mut circuit_gates[12].wires, 0, &mut wires, (1, 4));
        // Copy remainder1 -> Next(5)
        connect_cell_pair(&mut circuit_gates[13].wires, 0, &mut wires, (1, 5));
        // Copy remainder2 -> Next(6)
        connect_cell_pair(&mut circuit_gates[14].wires, 0, &mut wires, (1, 6));

        circuit_gates.append(&mut vec![
            CircuitGate {
                typ: GateType::ForeignFieldMul,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: wires[1],
                coeffs: vec![],
            },
        ]);

        (start_row + circuit_gates.len(), circuit_gates)
    }

    pub fn verify_foreign_field_mul(
        &self,
        _: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> CircuitGateResult<()> {
        if !circuit_gates().contains(&self.typ) {
            return Err(CircuitGateError::InvalidCircuitGateType(self.typ));
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
            .map_err(|_| CircuitGateError::InvalidCopyConstraint(self.typ))?;

        // Compute witness polynomial evaluations
        let witness_evals = cs.evaluate(&witness_poly, &z_poly);

        let mut index_evals = HashMap::new();
        index_evals.insert(
            self.typ,
            &cs.foreign_field_mul_selector_polys[circuit_gate_selector_index(self.typ)].eval8,
        );

        // Set up lookup environment
        let lcs = cs
            .lookup_constraint_system
            .as_ref()
            .ok_or(CircuitGateError::MissingLookupConstraintSystem(self.typ))?;

        let lookup_env_data = set_up_lookup_env_data(
            self.typ,
            cs,
            &witness,
            &beta,
            &gamma,
            &lcs.configuration.lookup_info,
        )
        .map_err(|e| e)?;
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
                    foreign_field_modulus: vec![],
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
            Err(CircuitGateError::InvalidConstraint(self.typ))
        }
    }
}

// Connect the pair of cells in different wires vectors, specified by the
// wires1, col1 and wires2, cell2 parameters
//
// cell1 --> cell2 && cell2 --> cell1
//
// Cell format is: (row, col)
//
// Note: This function assumes that the targeted cells are freshly instantiated
//       with self-connections.  If the two cells are transitively already part
//       of the same permutation then this would split it.
fn connect_cell_pair(
    wires1: &mut GateWires,
    col1: usize,
    wires2: &mut [GateWires],
    cell2: (usize, usize),
) {
    std::mem::swap(&mut wires1[col1], &mut wires2[cell2.0][cell2.1]);
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
) -> CircuitGateResult<LookupEnvironmentData<F>> {
    let lcs = cs
        .lookup_constraint_system
        .as_ref()
        .ok_or(CircuitGateError::MissingLookupConstraintSystem(gate_type))?;

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
    .map_err(|_| CircuitGateError::InvalidLookupConstraintSorted(gate_type))?;

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
    .map_err(|_| CircuitGateError::InvalidLookupConstraintAggregation(gate_type))?;

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
        GateType::ForeignFieldMul => 0,
        _ => panic!("invalid gate type"),
    }
}

/// Get vector of foreign field multiplication circuit gate types
pub fn circuit_gates() -> Vec<GateType> {
    vec![GateType::ForeignFieldMul]
}

/// Get combined constraints for a given foreign field multiplication circuit gate
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::ForeignFieldMul => ForeignFieldMul::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Number of constraints for a given foreign field mul circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::ForeignFieldMul => ForeignFieldMul::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all foreign field multiplication circuit gates
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    ForeignFieldMul::combined_constraints(alphas)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    fn _biguint_from_hex_le(hex: &str) -> BigUint {
        let mut bytes = hex::decode(hex).expect("invalid hex");
        bytes.reverse();
        BigUint::from_bytes_le(&bytes)
    }
}
