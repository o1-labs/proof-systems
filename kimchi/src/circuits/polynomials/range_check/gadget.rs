//! Range check gate

use ark_ff::{FftField, PrimeField, SquareRootField};

use crate::circuits::{
    gate::{CircuitGate, Connect},
    lookup::{
        self,
        tables::{GateLookupTable, LookupTable},
    },
    polynomials::zero::Zero,
    wires::Wire,
};

use super::circuitgates::{RangeCheck0, RangeCheck1};

pub const GATE_COUNT: usize = 2;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create range check gate for constraining three 88-bit values.
    ///     Inputs the starting row
    ///     Outputs tuple (`next_row`, `circuit_gates`) where
    ///       `next_row`      - next row after this gate
    ///       `circuit_gates` - vector of circuit gates comprising this gate
    pub fn create_multi_range_check(start_row: usize) -> (usize, Vec<Self>) {
        Self::create_multi_range_check_gadget(start_row, false)
    }

    /// Create range check gate for constraining compact limbs.
    ///     Inputs the starting row
    ///     Outputs tuple (`next_row`, `circuit_gates`) where
    ///       `next_row`      - next row after this gate
    ///       `circuit_gates` - vector of circuit gates comprising this gate
    pub fn create_compact_multi_range_check(start_row: usize) -> (usize, Vec<Self>) {
        Self::create_multi_range_check_gadget(start_row, true)
    }

    /// Create foreign field muti-range-check gadget by extending the existing gates
    pub fn extend_multi_range_check(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_multi_range_check(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Create foreign field muti-range-check gadget by extending the existing gates
    pub fn extend_compact_multi_range_check(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_compact_multi_range_check(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    /// Create single range check gate
    ///     Inputs the starting row
    ///     Outputs tuple (`next_row`, `circuit_gates`) where
    ///       `next_row`      - next row after this gate
    ///       `circuit_gates` - vector of circuit gates comprising this gate
    pub fn create_range_check(start_row: usize) -> (usize, Vec<Self>) {
        let gate = CircuitGate::new(
            RangeCheck0::<F>::typ(),
            Wire::for_row(start_row),
            vec![F::zero()],
        );
        (start_row + 1, vec![gate])
    }

    /// Create foreign field range-check gate by extending the existing gates
    pub fn extend_range_check(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_range_check(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    // Create range check gate for constraining three 88-bit values.
    //     Inputs the starting row and whether the limbs are in compact format
    //     Outputs tuple (`next_row`, `circuit_gates`) where
    //       `next_row`      - next row after this gate
    //       `circuit_gates` - vector of circuit gates comprising this gate
    fn create_multi_range_check_gadget(start_row: usize, compact: bool) -> (usize, Vec<Self>) {
        let coeff = if compact { F::one() } else { F::zero() };

        let mut circuit_gates = vec![
            CircuitGate::new(
                RangeCheck0::<F>::typ(),
                Wire::for_row(start_row),
                vec![F::zero()],
            ),
            CircuitGate::new(
                RangeCheck0::<F>::typ(),
                Wire::for_row(start_row + 1),
                vec![coeff],
            ),
            CircuitGate::new(
                RangeCheck1::<F>::typ(),
                Wire::for_row(start_row + 2),
                vec![],
            ),
            CircuitGate::new(Zero::<F>::typ(), Wire::for_row(start_row + 3), vec![]),
        ];

        // copy v0p0
        circuit_gates.connect_cell_pair((0, 1), (3, 3));

        // copy v0p1
        circuit_gates.connect_cell_pair((0, 2), (3, 4));

        // copy v1p0
        circuit_gates.connect_cell_pair((1, 1), (3, 5));

        // copy v1p1
        circuit_gates.connect_cell_pair((1, 2), (3, 6));

        (start_row + circuit_gates.len(), circuit_gates)
    }
}

/// Get the range check lookup table
pub fn lookup_table<F: FftField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}
