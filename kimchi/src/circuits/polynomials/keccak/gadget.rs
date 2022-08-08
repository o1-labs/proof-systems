//! Keccak gate

use ark_ff::{FftField, PrimeField};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::Argument,
        expr::E,
        gate::{CircuitGate, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        wires::Wire,
    },
};

use super::circuitgates::Xor;

pub const GATE_COUNT: usize = 1;

impl<F: PrimeField> CircuitGate<F> {
    /// Create Keccak xor gadget for constraining 64-bit xor.
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_keccak_xor(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::Xor,
                wires: Wire::new(start_row),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(start_row + 1),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Xor,
                wires: Wire::new(start_row + 2),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(start_row + 3),
                coeffs: vec![],
            },
        ];

        // TODO: copies when other gates are added using connect_cell_pair

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create single 32-bit xor gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_xor(start_row: usize) -> (usize, Vec<Self>) {
        (
            start_row + 2,
            vec![
                CircuitGate {
                    typ: GateType::Xor,
                    wires: Wire::new(start_row),
                    coeffs: vec![],
                },
                CircuitGate {
                    typ: GateType::Zero,
                    wires: Wire::new(start_row + 1),
                    coeffs: vec![],
                },
            ],
        )
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::Xor]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::RangeCheck0 => Xor::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::Xor => Xor::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    Xor::combined_constraints(alphas)
}

/// Get the range check lookup table
pub fn lookup_table<F: FftField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}
