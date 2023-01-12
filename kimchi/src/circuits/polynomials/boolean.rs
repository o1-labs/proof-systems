//! Boolean gate
//!
//! This gate constrains at most 7 boolean values: b0, b1, ..., b6
//!
//! Each boolean b is constrained with the degree-2 constraint `b * (b - 1)`
//!
//! Layout
//!
//! | col | `Boolean`   |
//! | --- | ----------- |
//! |   0 | `b0` (copy) |
//! |   1 | `b1` (copy) |
//! |   2 | `b2` (copy) |
//! |   3 | `b3` (copy) |
//! |   4 | `b4` (copy) |
//! |   5 | `b5` (copy) |
//! |   6 | `b6` (copy) |
//! |   7 |             |
//! |   8 |             |
//! |   9 |             |
//! |  10 |             |
//! |  11 |             |
//! |  12 |             |
//! |  13 |             |
//! |  14 |             |
//!
//! Constraints
//!
//!   1) b0 * (b0 - 1)
//!   2) b1 * (b1 - 1)
//!   3) b2 * (b2 - 1)
//!   4) b3 * (b3 - 1)
//!   5) b4 * (b4 - 1)
//!   6) b5 * (b5 - 1)
//!   7) b6 * (b6 - 1)
//!

use std::{array, marker::PhantomData};

use ark_ff::{PrimeField, SquareRootField};

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::{Wire, PERMUTS},
        witness::{self, ConstantCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};

/// Boolean gate
///    * This gate operates on the Curr row only
///    * Can constrain up to 7 boolean values
#[derive(Default)]
pub struct Boolean<F>(PhantomData<F>);

impl<F> Argument<F> for Boolean<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Boolean);
    const CONSTRAINTS: u32 = 7;
    // DEGREE is 2

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // C1-C7: Constrain b0, ..., b6 as boolean values
        (0..PERMUTS)
            .map(|i| env.witness_curr(i).boolean())
            .collect::<Vec<T>>()
    }
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create boolean gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_boolean(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::Boolean,
            wires: Wire::for_row(start_row),
            coeffs: vec![],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create generic boolean gate by extending the existing gates
    pub fn extend_boolean(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_boolean(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }
}

// Witness layout
fn layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 1] {
    [[
        VariableCell::create("b0"),
        VariableCell::create("b1"),
        VariableCell::create("b2"),
        VariableCell::create("b3"),
        VariableCell::create("b4"),
        VariableCell::create("b5"),
        VariableCell::create("b6"),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
        ConstantCell::create(F::zero()),
    ]]
}

/// Create witness for boolean gate
pub fn create<F: PrimeField>(values: &[F; PERMUTS]) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("b0" => values[0],
                                 "b1" => values[1],
                                 "b2" => values[2],
                                 "b3" => values[3],
                                 "b4" => values[4],
                                 "b5" => values[5],
                                 "b6" => values[6]),
    );

    witness
}

/// Extend an existing witness with a boolean gate
pub fn extend<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], values: &[F; PERMUTS]) {
    let boolean_witness = create(values);
    for col in 0..COLUMNS {
        witness[col].extend(boolean_witness[col].iter())
    }
}
