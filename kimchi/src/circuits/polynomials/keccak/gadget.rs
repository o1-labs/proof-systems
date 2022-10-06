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
        polynomials::generic::GenericGateSpec,
        wires::Wire,
    },
};

use super::circuitgates::{KeccakBits, KeccakRot, KeccakXor};

pub const GATE_COUNT: usize = 3;

impl<F: PrimeField> CircuitGate<F> {
    /// Create Keccak gadget. Right now it includes:
    /// - Generic gate with public input zero to constrain 64-bit length
    /// - 3 RangeCheck0 for the inputs and output
    /// - 2 KeccakBits gate for the bit decomposition of the inputs and output
    /// - 2 Keccak xor gadgets for one 64-bit value
    ///     
    /// Outputs tuple (next_row, circuit_gates) where
    ///  next_row      - next row after this gate
    ///  circuit_gates - vector of circuit gates comprising this gate
    pub fn create_keccak(start_row: usize) -> (usize, Vec<Self>) {
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
                typ: GateType::KeccakBits,
                wires: Wire::new(new_row + 1),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::KeccakBits,
                wires: Wire::new(new_row + 2),
                coeffs: vec![],
            },
        ]);

        gates.append(&mut vec![
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
            CircuitGate {
                typ: GateType::KeccakXor,
                wires: Wire::new(new_row + 5),
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::new(new_row + 6),
                coeffs: vec![],
            },
        ]);

        let rc_row = 1;
        let bit_row = 4;
        let xor_row = 6;

        // Copy first input from RC row to Bit row
        gates.connect_cell_pair((rc_row, 0), (bit_row, 0));
        // Copy first input low half from Xor row to Bit row
        gates.connect_cell_pair((bit_row, 1), (xor_row, 0));
        // Copy first input high half from Xor row to Bit row
        gates.connect_cell_pair((bit_row, 2), (xor_row + 2, 0));

        // Copy second input from RC row to Bit row
        gates.connect_cell_pair((rc_row + 1, 0), (bit_row, 3));
        // Copy second input low half from Xor row to Bit row
        gates.connect_cell_pair((bit_row, 4), (xor_row + 1, 1));
        // Copy second input high half from Xor row to Bit row
        gates.connect_cell_pair((bit_row, 5), (xor_row + 3, 1));

        // Copy output from RC row to Bit row
        gates.connect_cell_pair((rc_row + 2, 0), (bit_row + 1, 0));
        // Copy output low half from Xor row to Bit row
        gates.connect_cell_pair((bit_row + 1, 1), (xor_row + 1, 0));
        // Copy output high half from Xor row to Bit row
        gates.connect_cell_pair((bit_row + 1, 2), (xor_row + 3, 0));

        // TODO: copies when other gates are added using connect_cell_pair

        (start_row + gates.len(), gates)
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [
        GateType::KeccakXor,
        GateType::KeccakBits,
        GateType::KeccakRot,
    ]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: PrimeField>(typ: GateType) -> u32 {
    match typ {
        GateType::KeccakXor => KeccakXor::<F>::CONSTRAINTS,
        GateType::KeccakBits => KeccakBits::<F>::CONSTRAINTS,
        GateType::KeccakRot => KeccakRot::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: PrimeField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::KeccakXor => KeccakXor::combined_constraints(alphas),
        GateType::KeccakBits => KeccakBits::<F>::combined_constraints(alphas),
        GateType::KeccakRot => KeccakRot::<F>::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: PrimeField>(alphas: &Alphas<F>) -> E<F> {
    KeccakXor::combined_constraints(alphas)
        + KeccakBits::combined_constraints(alphas)
        + KeccakRot::combined_constraints(alphas)
}

/// Get the range check lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}
