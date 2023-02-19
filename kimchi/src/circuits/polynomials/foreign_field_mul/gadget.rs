//! This module obtains the gates of a foreign field addition circuit.

use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::foreign_field::BigUintForeignFieldHelpers;

use crate::{
    alphas::Alphas,
    circuits::{
        argument::Argument,
        expr::{Cache, E},
        gate::{CircuitGate, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        wires::Wire,
    },
};

use super::circuitgates::ForeignFieldMul;

/// Number of gates in this gadget
pub const GATE_COUNT: usize = 1;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create foreign field multiplication gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_foreign_field_mul(
        start_row: usize,
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        let neg_foreign_field_modulus = foreign_field_modulus.negate().to_field_limbs::<F>();
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::ForeignFieldMul,
                wires: Wire::for_row(start_row),
                coeffs: [foreign_field_modulus, neg_foreign_field_modulus]
                    .concat()
                    .to_vec(),
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::for_row(start_row + 1),
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create foreign field multiplication gate by extending the existing gates
    pub fn extend_foreign_field_mul(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        foreign_field_modulus: &BigUint,
    ) {
        let (next_row, circuit_gates) =
            Self::create_foreign_field_mul(*curr_row, foreign_field_modulus);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }
}

// TODO: Check do we use this anywhere
pub fn circuit_gate_selector_index(typ: GateType) -> usize {
    match typ {
        GateType::ForeignFieldMul => 0,
        _ => panic!("invalid gate type"),
    }
}

/// Get vector of foreign field multiplication circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::ForeignFieldMul]
}

/// Get combined constraints for a given foreign field multiplication circuit gate
pub fn circuit_gate_constraints<F: PrimeField>(
    typ: GateType,
    alphas: &Alphas<F>,
    cache: &mut Cache,
) -> E<F> {
    match typ {
        GateType::ForeignFieldMul => ForeignFieldMul::combined_constraints(alphas, cache),
        _ => panic!("invalid gate type"),
    }
}

/// Number of constraints for a given foreign field mul circuit gate type
pub fn circuit_gate_constraint_count<F: PrimeField>(typ: GateType) -> u32 {
    match typ {
        GateType::ForeignFieldMul => ForeignFieldMul::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all foreign field multiplication circuit gates
pub fn combined_constraints<F: PrimeField>(alphas: &Alphas<F>, cache: &mut Cache) -> E<F> {
    ForeignFieldMul::combined_constraints(alphas, cache)
}

/// Get the foreign field multiplication lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}
