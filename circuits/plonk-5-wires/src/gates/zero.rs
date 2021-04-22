use algebra::FftField;
use crate::gate::{CircuitGate};
use crate::wires::{GateWires};

pub trait ZeroGateType
{
    const ZERO: Self;
}

impl<F: FftField, GateType: ZeroGateType> CircuitGate<F, GateType>
{
    // this function creates "empty" circuit gate
    pub fn zero(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::ZERO,
            c: Vec::new(),
            wires,
        }
    }
}
