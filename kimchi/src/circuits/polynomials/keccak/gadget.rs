//! Keccak gate

use ark_ff::PrimeField;

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
        wires::Wire,
    },
};

use super::circuitgates::Xor16;

pub const GATE_COUNT: usize = 1;

impl<F: PrimeField> CircuitGate<F> {
    /// Create 64-bit word XOR gadget.
    /// - Generic gate with public input zero to constrain 64-bit length
    /// - 4 Xor16 for the inputs and output
    /// - 1 Zero  for completeness
    ///     
    /// Outputs tuple (next_row, circuit_gates) where
    ///  next_row  - next row after this gate
    ///  gates     - vector of circuit gates comprising this gate
    pub fn create_xor64(new_row: usize) -> (usize, Vec<Self>) {
        let gates = vec![
            CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::new(new_row),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::new(new_row + 1),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::new(new_row + 2),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Xor16,
                wires: Wire::new(new_row + 3),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(new_row + 4),
                coeffs: vec![],
            },
        ];

        (new_row + 5, gates)
    }

    /// Create the Keccak gadget
    /// TODO: right now it only creates a Generic gate followed by the Xor64 gates
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let zero_row = new_row;
        let mut gates = vec![CircuitGate {
            typ: GateType::Generic,
            wires: Wire::new(zero_row),
            coeffs: vec![],
        }];

        // Create gates for Xor 64
        let xor_row = zero_row + 1;
        let (new_row, mut xor64_gates) = Self::create_xor64(xor_row);
        // Append them to the full gates vector
        gates.append(&mut xor64_gates);
        // Check that in1_4, in2_4, out_4 are zero
        gates.connect_cell_pair((zero_row, 0), (xor_row + 4, 0));
        gates.connect_cell_pair((zero_row, 1), (xor_row + 4, 1));
        gates.connect_cell_pair((zero_row, 2), (xor_row + 4, 2));

        (new_row, gates)
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::Xor16]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: PrimeField>(typ: GateType) -> u32 {
    match typ {
        GateType::Xor16 => Xor16::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: PrimeField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::Xor16 => Xor16::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: PrimeField>(alphas: &Alphas<F>) -> E<F> {
    Xor16::combined_constraints(alphas)
}

/// Get the range check lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}
