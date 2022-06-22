use ark_ff::{FftField, SquareRootField};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::Argument,
        constraints::ConstraintSystem,
        expr::E,
        gate::{CircuitGate, CircuitGateResult, GateType},
        polynomial::COLUMNS,
    },
};

use super::ForeignFieldMul0;

impl<F: FftField + SquareRootField> CircuitGate<F> {
    pub fn verify_foreign_field_mul(
        &self,
        _: usize,
        _witness: &[Vec<F>; COLUMNS],
        _cs: &ConstraintSystem<F>,
    ) -> CircuitGateResult<()> {
        Ok(())
    }
}

/// Get vector of foreign field multiplication circuit gate types
pub fn circuit_gates() -> Vec<GateType> {
    vec![GateType::ForeignFieldMul0]
}

/// Get combined constraints for a given foreign field multiplication circuit gate
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::ForeignFieldMul0 => ForeignFieldMul0::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all foreign field multiplication circuit gates
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    ForeignFieldMul0::combined_constraints(alphas)
}
