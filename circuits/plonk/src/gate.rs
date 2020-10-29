/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use algebra::FftField;
pub use super::{wires::{GateWires, Wires, COLUMNS}, constraints::ConstraintSystem};

#[derive(Clone)]
#[derive(PartialEq)]
pub enum GateType
{
    Zero,       // zero gate
    Generic,    // generic arithmetic gate
    Poseidon,   // Poseidon permutation gate
    Add,        // Gate constraining EC addition in Affine form
    Double,     // Gate constraining EC point doubling in Affine form
    Vbmul1,     // Gate constraining EC variable base scalar multiplication 
    Vbmul2,     // Gate constraining unpacking EC variable base scalar multiplication 
    Endomul,    // Gate constraining EC variable base scalar multiplication with group endomorphim optimization
    Pack,       // Gate constraining packing
}

#[derive(Clone)]
pub struct CircuitGate<F: FftField>
{
    pub row: usize,         // row position in the circuit
    pub typ: GateType,      // type of the gate
    pub wires: GateWires,   // gate wires
    pub c: Vec<F>,          // constraints vector
}

impl<F: FftField> CircuitGate<F>
{
    // this function creates "empty" circuit gate
    pub fn zero(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Zero,
            c: Vec::new(),
            wires,
        }
    }

    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS], cs: &ConstraintSystem<F>) -> bool
    {
        match self.typ
        {
            GateType::Zero      => true,
            GateType::Generic   => self.verify_generic(witness),
            GateType::Poseidon  => self.verify_poseidon(witness, cs),
            GateType::Add       => self.verify_add(witness),
            GateType::Double    => self.verify_double(witness),
            GateType::Vbmul1    => self.verify_vbmul1(witness),
            GateType::Vbmul2    => self.verify_vbmul2(witness),
            GateType::Endomul   => self.verify_endomul(witness, cs),
            GateType::Pack      => self.verify_pack(witness),
        }
    }
}

#[derive(Clone)]
pub struct Gate<F: FftField>
{
    pub typ: GateType,      // type of the gate
    pub wires: Wires,       // gate wires
    pub c: Vec<F>,          // constraints vector
}
