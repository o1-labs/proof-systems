//! Conditional gate
//!
//! This gate implements at most 2 conditional statements per row
//!
//! ```text
//!     if(b, x, y) = b * x + (1 - b) * y
//!```
//!
//! Layout
//!
//! | col | `Conditional` |
//! | --- | ------------- |
//! |   0 | `r1`   (copy) |
//! |   1 | `x1`   (copy) |
//! |   2 | `y1`   (copy) |
//! |   3 | `r2`   (copy) |
//! |   4 | `x2`   (copy) |
//! |   5 | `y2`   (copy) |
//! |   6 | `b`    (copy) |
//! |   7 | `b1`          |
//! |   8 | `b2`          |
//! |   9 |               |
//! |  10 |               |
//! |  11 |               |
//! |  12 |               |
//! |  13 |               |
//! |  14 |               |
//!
//! where b1 and b2 \in [0, 1] and b = b1b2 \in [0, 3].
//!
//! Constraints
//!
//!   1) (b - 3) * (b - 2) * (b - 1) * b
//!   2) b = 2 * b1 + b2
//!   3) r1 = b1 * x1 + (1 - b1) * y1
//!   4) r2 = b2 * x2 + (1 - b2) * y2
//!

use std::{array, marker::PhantomData};

use ark_ff::{PrimeField, SquareRootField};

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::constraints::ExprOps,
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::Wire,
        witness::{self, ConstantCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};

/// Conditional gate
///    * This gate operates on the Curr row only
///    * Can constrain up to two conditional expressions
#[derive(Default)]
pub struct Conditional<F>(PhantomData<F>);

impl<F> Argument<F> for Conditional<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Conditional);
    const CONSTRAINTS: u32 = 4;
    // DEGREE is 4

    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        // Outputs r1 and r2
        let output = [env.witness_curr(0), env.witness_curr(3)];

        // Operands x1 and x2
        let x = [env.witness_curr(1), env.witness_curr(4)];

        // Operands y1 and y2
        let y = [env.witness_curr(2), env.witness_curr(5)];

        // Condition values b, b1 and b2
        let b = env.witness_curr(6);
        let b1 = env.witness_curr(7);
        let b2 = env.witness_curr(8);

        // C1: Constrain b \in [0, 3]
        constraints.push(b.crumb());

        // C2: b = 2 * b1 + b2
        constraints.push(b - (T::from(2u64) * b1.clone() + b2.clone()));

        // C3: r1 = b1 * x1 + (1 - b1) * y1
        constraints
            .push(output[0].clone() - (b1.clone() * x[0].clone() + (T::one() - b1) * y[0].clone()));

        // C4: r2 = b2 * x2 + (1 - b2) * y2
        constraints
            .push(output[1].clone() - (b2.clone() * x[1].clone() + (T::one() - b2) * y[1].clone()));

        constraints
    }
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create if conditional gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_conditional(start_row: usize) -> (usize, Vec<Self>) {
        let circuit_gates = vec![CircuitGate {
            typ: GateType::Conditional,
            wires: Wire::for_row(start_row),
            coeffs: vec![],
        }];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create if conditional gate by extending the existing gates
    pub fn extend_conditional(gates: &mut Vec<Self>, curr_row: &mut usize) {
        let (next_row, circuit_gates) = Self::create_conditional(*curr_row);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }
}

fn layout<F: PrimeField>() -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 1] {
    [
        // Conditional   row
        [
            VariableCell::create("r1"),
            VariableCell::create("x1"),
            VariableCell::create("y1"),
            VariableCell::create("r2"),
            VariableCell::create("x2"),
            VariableCell::create("y2"),
            VariableCell::create("b"),
            VariableCell::create("b1"),
            VariableCell::create("b2"),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
            ConstantCell::create(F::zero()),
        ],
    ]
}

/// Create an if conditional witness
pub fn create<F: PrimeField>(x: &[F; 2], y: &[F; 2], b: &[bool; 2]) -> [Vec<F>; COLUMNS] {
    let [b1, b2] = b.map(|x| if x { F::one() } else { F::zero() });
    let b = F::from(2u64) * b1 + b2;
    let r1 = b1 * x[0] + (F::one() - b1) * y[0];
    let r2 = b2 * x[1] + (F::one() - b2) * y[1];

    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness::init(
        &mut witness,
        0,
        &layout(),
        &variable_map!("r1" => r1,
                                 "x1" => x[0],
                                 "y1" => y[0],
                                 "r2" => r2,
                                 "x2" => x[1],
                                 "y2" => y[1],
                                 "b" => b,
                                 "b1" => b1,
                                 "b2" => b2),
    );

    witness
}

/// Extend an existing witness with a conditional gate
pub fn extend<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    x: &[F; 2],
    y: &[F; 2],
    b: &[bool; 2],
) {
    let limbs_witness = create(x, y, b);
    for col in 0..COLUMNS {
        witness[col].extend(limbs_witness[col].iter())
    }
}
