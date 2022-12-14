//! This module obtains the gates of a foreign field addition circuit.

use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::foreign_field::BigUintForeignFieldHelpers;

use crate::circuits::{
    gate::{CircuitGate, GateType},
    wires::Wire,
};

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
}
