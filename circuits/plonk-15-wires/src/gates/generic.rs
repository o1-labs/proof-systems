/*****************************************************************************************************************

This source file implements Plonk generic constraint gate primitive.

*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS, GENERICS};
use ark_ff::FftField;
use array_init::array_init;

pub const MUL_COEFF: usize = GENERICS;
pub const CONSTANT_COEFF: usize = GENERICS + 1;

impl<F: FftField> CircuitGate<F> {
    // TODO(mimoo): why qw is length 15 if the polynomial side only uses 3?
    pub fn create_generic(row: usize, wires: GateWires, qw: [F; COLUMNS], qm: F, qc: F) -> Self {
        let mut c = qw.to_vec();
        c.push(qm);
        c.push(qc);

        CircuitGate {
            row,
            typ: GateType::Generic,
            wires,
            c,
        }
    }

    /// creates an addition gate
    pub fn create_generic_add(row: usize, wires: GateWires) -> Self {
        let on = F::one();
        let off = F::zero();
        let qw: [F; COLUMNS] = array_init(|col| {
            if col < 2 {
                on
            } else if col == 2 {
                -on
            } else {
                off
            }
        });
        Self::create_generic(row, wires, qw, off, off)
    }

    /// creates a multiplication gate
    pub fn create_generic_mul(row: usize, wires: GateWires) -> Self {
        let on = F::one();
        let off = F::zero();
        let qw: [F; COLUMNS] = array_init(|col| if col == 2 { on } else { off });
        Self::create_generic(row, wires, qw, -on, off)
    }

    /// creates a constant gate
    pub fn create_generic_const(row: usize, wires: GateWires, constant: F) -> Self {
        let on = F::one();
        let off = F::zero();
        let qw: [F; COLUMNS] = array_init(|col| if col == 0 { on } else { off });
        Self::create_generic(row, wires, qw, off, -constant)
    }

    /// creates a public input gate
    pub fn create_generic_public(row: usize, wires: GateWires) -> Self {
        let on = F::one();
        let off = F::zero();
        let qw: [F; COLUMNS] = array_init(|col| if col == 0 { on } else { off });
        Self::create_generic(row, wires, qw, off, off)
    }

    /// verifies that the generic gate constraints are solved by the witness
    // TODO(mimoo): this is not going to work for public inputs no?
    pub fn verify_generic(&self, witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        // assignments
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let left = this[0];
        let right = this[1];

        // selector vectors
        let mul_selector = self.c[COLUMNS];
        let constant_selector = self.c[COLUMNS + 1];

        // constants
        let zero = F::zero();

        // check if it's the correct gate
        ensure_eq!(self.typ, GateType::Generic, "generic: incorrect gate");

        // toggling each column x[i] depending on the selectors c[i]
        let sum = (0..GENERICS)
            .map(|i| self.c[i] * &this[i])
            .fold(zero, |x, y| x + &y);

        // multiplication
        let mul = mul_selector * &left * &right;
        ensure_eq!(
            zero,
            sum + &mul + &constant_selector,
            "generic: incorrect sum"
        );

        // TODO(mimoo): additional checks:
        // - if both left and right wire are set, then output must be set
        // - if constant wire is set, then left wire must be set

        // all good
        return Ok(());
    }

    pub fn generic(&self) -> F {
        if self.typ == GateType::Generic {
            F::one()
        } else {
            F::zero()
        }
    }
}
