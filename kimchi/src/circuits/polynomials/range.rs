use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{prologue::*, Cache},
    gate::{CircuitGate, GateType},
    wires::{GateWires, COLUMNS},
};
use ark_ff::{FftField, Field, One};

impl<F: FftField> CircuitGate<F> {
    pub fn create_range(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::Range,
            wires,
            coeffs: vec![],
        }
    }
}
