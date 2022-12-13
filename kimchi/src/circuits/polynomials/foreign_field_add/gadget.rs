//! This module obtains the gates of a foreign field addition circuit.

use std::collections::HashMap;

use ark_ff::{PrimeField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use num_bigint::BigUint;
use o1_utils::foreign_field::BigUintForeignFieldHelpers;
use rand::{prelude::StdRng, SeedableRng};
use std::array;

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        expr::{self, l0_1, Environment},
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, GateType},
        polynomial::COLUMNS,
        wires::Wire,
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};

use super::circuitgates::ForeignFieldAdd;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create foreign field addition gate chain without range checks (needs to wire the range check for result bound manually)
    ///     Inputs
    ///         starting row
    ///         number of addition gates
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    ///
    /// Note that te final structure of the circuit is as follows:
    /// circuit_gates = [
    ///      {
    ///        [i] ->      -> 1 ForeignFieldAdd row
    ///      } * num times
    ///      [n]           -> 1 ForeignFieldAdd row (this is where the final result goes)
    ///      [n+1]         -> 1 Zero row for bound result
    /// ]
    ///
    pub fn create(
        start_row: usize,
        num: usize,
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        let next_row = start_row;
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let mut circuit_gates = vec![];

        // Foreign field addition gates
        // ---------------------------
        // First the single-addition gates
        for i in 0..num {
            circuit_gates.append(&mut vec![CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(next_row + i),
                coeffs: foreign_field_modulus.to_vec(),
            }]);
        }
        // Then the final bound gate and the zero gate
        circuit_gates.append(&mut vec![
            CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(next_row + num),
                coeffs: foreign_field_modulus.to_vec(),
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::for_row(next_row + num + 1),
                coeffs: vec![],
            },
        ]);
        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create a single foreign field addition gate
    ///     Inputs
    ///         starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_single_ffadd(
        start_row: usize,
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(start_row),
                coeffs: foreign_field_modulus.to_vec(),
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::for_row(start_row + 1),
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create foreign field addition gate by extending the existing gates
    pub fn extend_single_foreign_field_add(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        foreign_field_modulus: &BigUint,
    ) {
        let (next_row, circuit_gates) = Self::create_single_ffadd(*curr_row, foreign_field_modulus);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Verifies the foreign field addition gadget
    pub fn verify_foreign_field_add<G: KimchiCurve<ScalarField = F>>(
        &self,
        _: usize,
        witness: &[Vec<F>; COLUMNS],
        index: &ProverIndex<G>,
    ) -> CircuitGateResult<()> {
        if GateType::ForeignFieldAdd != self.typ {
            return Err(CircuitGateError::InvalidCircuitGateType(self.typ));
        }

        // Pad the witness to domain d1 size
        let padding_length = index
            .cs
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
        let witness_poly: [DensePolynomial<F>; COLUMNS] = array::from_fn(|i| {
            Evaluations::<F, D<F>>::from_vec_and_domain(witness[i].clone(), index.cs.domain.d1)
                .interpolate()
        });

        // Compute permutation polynomial
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let z_poly = index
            .perm_aggreg(&witness, &beta, &gamma, rng)
            .map_err(|_| CircuitGateError::InvalidCopyConstraint(self.typ))?;

        // Compute witness polynomial evaluations
        let witness_evals = index.cs.evaluate(&witness_poly, &z_poly);

        let mut index_evals = HashMap::new();
        index_evals.insert(
            self.typ,
            index
                .column_evaluations
                .foreign_field_add_selector8
                .as_ref()
                .unwrap(),
        );

        // Set up the environment
        let env = {
            Environment {
                constants: expr::Constants {
                    alpha: F::rand(rng),
                    beta: F::rand(rng),
                    gamma: F::rand(rng),
                    joint_combiner: Some(F::rand(rng)),
                    endo_coefficient: index.cs.endo,
                    mds: &G::sponge_params().mds,
                },
                witness: &witness_evals.d8.this.w,
                coefficient: &index.column_evaluations.coefficients8,
                vanishes_on_last_4_rows: &index.cs.precomputations().vanishes_on_last_4_rows,
                z: &witness_evals.d8.this.z,
                l0_1: l0_1(index.cs.domain.d1),
                domain: index.cs.domain,
                index: index_evals,
                lookup: None,
            }
        };

        // Setup powers of alpha
        let mut alphas = Alphas::<F>::default();
        alphas.register(
            ArgumentType::Gate(self.typ),
            ForeignFieldAdd::<F>::CONSTRAINTS,
        );

        // Get constraints for this circuit gate
        let constraints = ForeignFieldAdd::combined_constraints(&alphas);

        // Verify it against the environment
        if constraints
            .evaluations(&env)
            .interpolate()
            .divide_by_vanishing_poly(index.cs.domain.d1)
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
