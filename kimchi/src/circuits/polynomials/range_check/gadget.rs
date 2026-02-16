//! Range check gate

use ark_ff::{FftField, PrimeField};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::Argument,
        berkeley_columns::E,
        expr::Cache,
        gate::{CircuitGate, Connect, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        wires::Wire,
    },
};

use super::circuitgates::{RangeCheck0, RangeCheck1};

pub const GATE_COUNT: usize = 2;

impl<F: PrimeField> CircuitGate<F> {
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
            GateType::RangeCheck0,
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
                GateType::RangeCheck0,
                Wire::for_row(start_row),
                vec![F::zero()],
            ),
            CircuitGate::new(
                GateType::RangeCheck0,
                Wire::for_row(start_row + 1),
                vec![coeff],
            ),
            CircuitGate::new(GateType::RangeCheck1, Wire::for_row(start_row + 2), vec![]),
            CircuitGate::new(GateType::Zero, Wire::for_row(start_row + 3), vec![]),
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

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> [GateType; GATE_COUNT] {
    [GateType::RangeCheck0, GateType::RangeCheck1]
}

/// Number of constraints for a given range check circuit gate type
///
/// # Panics
///
/// Will panic if `typ` is not `RangeCheck`-related gate type.
pub fn circuit_gate_constraint_count<F: PrimeField>(typ: GateType) -> u32 {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::<F>::CONSTRAINTS,
        GateType::RangeCheck1 => RangeCheck1::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
///
/// # Panics
///
/// Will panic if `typ` is not `RangeCheck`-related gate type.
pub fn circuit_gate_constraints<F: PrimeField>(
    typ: GateType,
    alphas: &Alphas<F>,
    cache: &mut Cache,
) -> E<F> {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::combined_constraints(alphas, cache),
        GateType::RangeCheck1 => RangeCheck1::combined_constraints(alphas, cache),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: PrimeField>(alphas: &Alphas<F>, cache: &mut Cache) -> E<F> {
    RangeCheck0::combined_constraints(alphas, cache)
        + RangeCheck1::combined_constraints(alphas, cache)
}

/// Get the range check lookup table
pub fn lookup_table<F: FftField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}
