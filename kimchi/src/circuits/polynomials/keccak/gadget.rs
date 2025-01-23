//! Keccak gadget
use crate::circuits::{
    gate::{CircuitGate, GateType},
    wires::Wire,
};
use ark_ff::PrimeField;

use super::{
    constants::{RATE_IN_BYTES, ROUNDS},
    Keccak, RC,
};

const SPONGE_COEFFS: usize = 336;

impl<F: PrimeField> CircuitGate<F> {
    /// Extends a Keccak circuit to hash one message
    /// Note:
    /// Requires at least one more row after the Keccak gadget so that
    /// constraints can access the next row in the squeeze
    pub fn extend_keccak(circuit: &mut Vec<Self>, bytelength: usize) -> usize {
        let mut gates = Self::create_keccak(circuit.len(), bytelength);
        circuit.append(&mut gates);
        circuit.len()
    }

    /// Creates a Keccak256 circuit, capacity 512 bits, rate 1088 bits, message
    /// of a given bytelength
    fn create_keccak(new_row: usize, bytelength: usize) -> Vec<Self> {
        let padded_len = Keccak::padded_length(bytelength);
        let extra_bytes = padded_len - bytelength;
        let num_blocks = padded_len / RATE_IN_BYTES;
        let mut gates = vec![];
        for block in 0..num_blocks {
            let root = block == 0;
            let pad = block == num_blocks - 1;
            gates.push(Self::create_keccak_absorb(
                new_row + gates.len(),
                root,
                pad,
                extra_bytes,
            ));
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
            coeffs: {
                let mut c = vec![F::zero(); SPONGE_COEFFS];
                c[1] = F::one();
                c
            },
        }
    }

    fn create_keccak_absorb(new_row: usize, root: bool, pad: bool, pad_bytes: usize) -> Self {
        let mut coeffs = vec![F::zero(); SPONGE_COEFFS];
        coeffs[0] = F::one(); // absorb
        if root {
            coeffs[2] = F::one(); // root
        }
        if pad {
            // Check pad 0x01 (0x00 ... 0x00)* 0x80 or 0x81 if only one byte for padding
            for i in 0..pad_bytes {
                coeffs[140 - i] = F::one(); // flag for padding
                if i == 0 {
                    coeffs[SPONGE_COEFFS - 1 - i] += F::from(0x80u8); // pad
                }
                if i == pad_bytes - 1 {
                    coeffs[SPONGE_COEFFS - 1 - i] += F::one(); // pad
                }
            }
        }
        CircuitGate {
            typ: GateType::KeccakSponge,
            wires: Wire::for_row(new_row),
            coeffs,
        }
    }

    fn create_keccak_round(new_row: usize, round: usize) -> Self {
        CircuitGate {
            typ: GateType::KeccakRound,
            wires: Wire::for_row(new_row),
            coeffs: Keccak::expand_word(RC[round]),
        }
    }
}
