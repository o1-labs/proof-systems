//! This module obtains the gates of a foreign field addition circuit.

use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::foreign_field::BigUintForeignFieldHelpers;

use crate::circuits::{
    gate::{CircuitGate, Connect, GateType},
    wires::Wire,
};

use super::witness::FFOps;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create foreign field addition gate chain without range checks (needs to wire the range check for result bound manually)
    ///     Inputs
    ///         starting row
    ///         operations to perform
    ///         modulus of the foreign field
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
    /// INTEGRATION:
    /// - Wire the range check for result bound manually
    /// - Connect to public input containing the 1 value for the overflow in the final bound check
    pub fn create_chain_ffadd(
        start_row: usize,
        opcodes: &[FFOps],
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        let next_row = start_row;
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let mut circuit_gates = vec![];
        let num = opcodes.len();
        // ---------------------------
        // Foreign field addition gates
        // ---------------------------
        // First the single-addition gates
        for i in 0..num {
            assert_ne!(opcodes[i], FFOps::Mul);
            let mut coeffs = foreign_field_modulus.to_vec();
            coeffs.push(opcodes[i].sign::<F>());
            circuit_gates.append(&mut vec![CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(next_row + i),
                coeffs,
            }]);
        }
        let mut final_coeffs = foreign_field_modulus.to_vec();
        final_coeffs.push(FFOps::Add.sign::<F>());
        // Then the final bound gate and the zero gate
        circuit_gates.append(&mut vec![
            CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(next_row + num),
                coeffs: final_coeffs,
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::for_row(next_row + num + 1),
                coeffs: vec![],
            },
        ]);
        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create a single foreign field addition gate. This is used for example in the final bound check.
    ///     Inputs
    ///         starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_single_ffadd(
        start_row: usize,
        operation: FFOps,
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        assert_ne!(operation, FFOps::Mul);
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let mut coeffs = foreign_field_modulus.to_vec();
        coeffs.push(operation.sign::<F>());
        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::ForeignFieldAdd,
                wires: Wire::for_row(start_row),
                coeffs,
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: Wire::for_row(start_row + 1),
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Extend a chain of foreign field addition gates. It already wires the public input to the overflow cell.
    pub fn extend_chain_ffadd(
        gates: &mut Vec<Self>,
        pub_row: usize,
        curr_row: &mut usize,
        opcodes: &[FFOps],
        foreign_field_modulus: &BigUint,
    ) {
        let (next_row, add_gates) =
            Self::create_chain_ffadd(*curr_row, opcodes, foreign_field_modulus);
        gates.extend_from_slice(&add_gates);
        *curr_row = next_row;
        // check overflow flag is one
        gates.connect_cell_pair((pub_row, 0), (*curr_row - 2, 6));
    }

    /// Extend a single foreign field addition gate followed by a zero row containing the result
    pub fn extend_single_ffadd(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        operation: FFOps,
        foreign_field_modulus: &BigUint,
    ) {
        let (next_row, add_gates) =
            Self::create_single_ffadd(*curr_row, operation, foreign_field_modulus);
        *curr_row = next_row;
        gates.extend_from_slice(&add_gates);
    }
}
