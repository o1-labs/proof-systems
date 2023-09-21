//! Keccak gadget
use crate::circuits::{
    gate::{CircuitGate, GateType},
    lookup::{
        self,
        tables::{GateLookupTable, LookupTable},
    },
    wires::Wire,
};
use ark_ff::{PrimeField, SquareRootField};

use super::{expand, RATE, RC, ROUNDS};

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Extends a Keccak circuit to hash one message (already padded to a multiple of 136 bits with 10*1 rule)
    pub fn extend_keccak(circuit: &mut Vec<Self>, bytelength: usize) -> usize {
        // pad
        let mut gates = Self::create_keccak(circuit.len(), bytelength);
        circuit.append(&mut gates);
        circuit.len()
    }

    /// Creates a Keccak256 circuit, capacity 512 bits, rate 1088 bits, for a padded message of a given bytelength
    fn create_keccak(new_row: usize, bytelength: usize) -> Vec<Self> {
        let mut gates = vec![];
        for block in 0..(bytelength / RATE) {
            if block == 0 {
                gates.push(Self::create_keccak_root(new_row + gates.len()));
            } else {
                gates.push(Self::create_keccak_absorb(new_row + gates.len()));
            }
            for round in 0..ROUNDS {
                gates.push(Self::create_keccak_round(new_row + gates.len(), round));
            }
        }
        gates.push(Self::create_keccak_squeeze(new_row + gates.len()));
        gates
    }

    fn create_keccak_squeeze(new_row: usize) -> Self {
        CircuitGate {
            typ: GateType::KeccakSponge,
            wires: Wire::for_row(new_row),
            coeffs: vec![F::zero(), F::zero(), F::one()],
        }
    }

    fn create_keccak_absorb(new_row: usize) -> Self {
        CircuitGate {
            typ: GateType::KeccakSponge,
            wires: Wire::for_row(new_row),
            coeffs: vec![F::zero(), F::one(), F::zero()],
        }
    }

    fn create_keccak_root(new_row: usize) -> Self {
        CircuitGate {
            typ: GateType::KeccakSponge,
            wires: Wire::for_row(new_row),
            coeffs: vec![F::one(), F::zero(), F::zero()],
        }
    }

    fn create_keccak_round(new_row: usize, round: usize) -> Self {
        CircuitGate {
            typ: GateType::KeccakRound,
            wires: Wire::for_row(new_row),
            coeffs: expand(RC[round]),
        }
    }
}

/// Get the Keccak lookup tables
pub fn lookup_table<F: PrimeField>() -> Vec<LookupTable<F>> {
    vec![
        lookup::tables::get_table::<F>(GateLookupTable::Sparse),
        lookup::tables::get_table::<F>(GateLookupTable::Bytes),
    ]
}
