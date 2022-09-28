//! Keccak gate

use ark_ff::{FftField, PrimeField};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::Argument,
        expr::E,
        gate::{CircuitGate, Connect, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        polynomials::generic::GenericGateSpec,
        wires::Wire,
    },
};

use super::circuitgates::KeccakXor;

pub const GATE_COUNT: usize = 1;

impl<F: PrimeField> CircuitGate<F> {
    /// Create Keccak xor gadget for constraining 64-bit xor.
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_keccak_xor(start_row: usize) -> (usize, Vec<Self>) {
        let mut gates = vec![];
        let zero_row = start_row;
        gates.push(CircuitGate::<F>::create_generic_gadget(
            Wire::new(start_row),
            GenericGateSpec::Pub,
            None,
        ));

        let mut new_row = start_row;
        for _ in 0..3 {
            // 64bit checks for 3 elements: input1, input2, and output
            new_row += 1;
            gates.append(&mut CircuitGate::<F>::create_range_check(new_row).1);
            gates.connect_64bit(zero_row, new_row);
        }

        gates.append(&mut vec![
            CircuitGate {
                typ: GateType::KeccakXor,
                wires: Wire::new(new_row + 1),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(new_row + 2),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::KeccakXor,
                wires: Wire::new(new_row + 3),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(new_row + 4),
                coeffs: vec![],
            },
        ]);

        // TODO: copies when other gates are added using connect_cell_pair

        (start_row + gates.len(), gates)
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::KeccakXor]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::KeccakXor => KeccakXor::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::KeccakXor => KeccakXor::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    KeccakXor::combined_constraints(alphas)
}

/// Get the range check lookup table
pub fn lookup_table<F: FftField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}
