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
        polynomials::{generic::GenericGateSpec, xor::Xor16},
        wires::Wire,
    },
};

use super::{constraints::KeccakRot, ROT_TAB};

pub const GATE_COUNT: usize = 2;

impl<F: PrimeField> CircuitGate<F> {
    /// Creates a KeccakRot gadget to rotate a word
    /// It will need:
    /// - 1 Generic gate to constrain to zero some limbs
    ///
    /// It has:
    /// - 1 KeccakRot gate to rotate the word
    /// - 1 RangeCheck0 to constrain the size of some parameters
    pub fn create_rot64(new_row: usize, x: usize, y: usize) -> (usize, Vec<Self>) {
        let gates = vec![
            CircuitGate {
                typ: GateType::KeccakRot,
                wires: Wire::new(new_row),
                coeffs: vec![F::from(2u64.pow(ROT_TAB[x % 5][y % 5]))],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: Wire::new(new_row + 1),
                coeffs: vec![],
            },
        ];
        (new_row + gates.len(), gates)
    }

    /// Create the Keccak rot
    /// TODO: right now it only creates a Generic gate followed by the KeccakRot gates
    pub fn create_keccak_rot(new_row: usize, x: usize, y: usize) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let zero_row = new_row;
        let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
            Wire::new(new_row),
            GenericGateSpec::Pub,
            None,
        )];

        // Create gates for Xor 64
        let rot_row = zero_row + 1;
        let (new_row, mut rot64_gates) = Self::create_rot64(rot_row, x, y);
        // Append them to the full gates vector
        gates.append(&mut rot64_gates);
        // Check that 2 most significant limbs of shifted are zero
        gates.connect_64bit(zero_row, rot_row + 1);

        (new_row, gates)
    }
}

impl<F: PrimeField> CircuitGate<F> {
    /// Create the Keccak gadget
    /// TODO: right now it only creates a Generic gate followed by the Xor64 gates
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        Self::create_xor(new_row, 64)
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::Xor16, GateType::KeccakRot]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: PrimeField>(typ: GateType) -> u32 {
    match typ {
        GateType::Xor16 => Xor16::<F>::CONSTRAINTS,
        GateType::KeccakRot => KeccakRot::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: PrimeField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::Xor16 => Xor16::combined_constraints(alphas),
        GateType::KeccakRot => KeccakRot::<F>::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: PrimeField>(alphas: &Alphas<F>) -> E<F> {
    Xor16::combined_constraints(alphas) + KeccakRot::combined_constraints(alphas)
}

/// Get the range check lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::Xor)
}
