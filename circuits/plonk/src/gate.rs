/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use algebra::FftField;
pub use super::{wires::GateWires, constraints::ConstraintSystem};
use oracle::poseidon::{PlonkSpongeConstants, SpongeConstants};

pub const SPONGE_WIDTH: usize = PlonkSpongeConstants::SPONGE_CAPACITY + PlonkSpongeConstants::SPONGE_RATE;

#[derive(Clone)]
#[derive(PartialEq)]
pub enum GateType
{
    Zero,       // zero gate
    Generic,    // generic arithmetic gate

    Poseidon,   // Poseidon permutation gate

    Add1,       // Gate constraining EC addition in Affine form
    Add2,       // Gate constraining EC point abscissa distinctness

    Vbmul1,     // Gate constraining EC variable base scalar multiplication
    Vbmul2,     // Gate constraining EC variable base scalar multiplication
    Vbmul3,     // Gate constraining EC variable base scalar multiplication

    Endomul1,   // Gate constraining EC variable base scalar multiplication with group endomorphim optimization
    Endomul2,   // Gate constraining EC variable base scalar multiplication with group endomorphim optimization
    Endomul3,   // Gate constraining EC variable base scalar multiplication with group endomorphim optimization
    Endomul4,   // Gate constraining EC variable base scalar multiplication with group endomorphim optimization
}

#[derive(Clone)]
pub struct CircuitGate<F: FftField>
{
    pub typ: GateType,      // type of the gate
    pub wires: GateWires,   // gate wires
    pub c: Vec<F>,          // constraints vector
}

impl<F: FftField> CircuitGate<F>
{
    // this function creates "empty" circuit gate
    pub fn zero(wires: GateWires) -> Self
    {
        CircuitGate
        {
            typ: GateType::Zero,
            c: Vec::new(),
            wires,
        }
    }

    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    pub fn verify(&self, next: &Self, witness: &Vec<F>, cs: &ConstraintSystem<F>) -> bool
    {
        match self.typ
        {
            GateType::Zero      => true,
            GateType::Generic   => self.verify_generic(witness),
            GateType::Poseidon  => self.verify_poseidon(next, witness),
            GateType::Add1      => self.verify_add1(next, witness),
            GateType::Add2      => self.verify_add2(witness),
            GateType::Vbmul1    => self.verify_vbmul1(next, witness),
            GateType::Vbmul2    => self.verify_vbmul2(next, witness),
            GateType::Vbmul3    => self.verify_vbmul3(next, witness),
            GateType::Endomul1  => self.verify_endomul1(next, witness, cs),
            GateType::Endomul2  => self.verify_endomul2(next, witness),
            GateType::Endomul3  => self.verify_endomul3(next, witness),
            GateType::Endomul4  => self.verify_endomul4(next, witness),
        }
    }
}
