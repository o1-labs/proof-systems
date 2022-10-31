//! Keccak gate

use ark_ff::PrimeField;

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
        polynomials::xor::Xor16,
    },
};

pub const GATE_COUNT: usize = 1;

impl<F: PrimeField> CircuitGate<F> {
    /// Create the Keccak gadget
    /// TODO: right now it only creates a Generic gate followed by the Xor64 gates
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        Self::create_xor(new_row, 64)
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
