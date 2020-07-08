/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use algebra::Field;

pub const SPONGE_WIDTH: usize = oracle::poseidon::SPONGE_CAPACITY + oracle::poseidon::SPONGE_RATE;

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
}

#[derive(Clone)]
pub struct CircuitGate<F: Field>
{
    pub typ: GateType,      // type of the gate
    
    pub l: (usize, usize),  // left input wire index and its permutation
    pub r: (usize, usize),  // right input wire index and its permutation
    pub o: (usize, usize),  // output wire index and its permutation

    pub c: Vec<F>,          // constraints vector
}

impl<F: Field> CircuitGate<F>
{
    // this function creates "empty" circuit gate
    pub fn zero
    (
        l: (usize, usize),
        r: (usize, usize),
        o: (usize, usize),
    ) -> Self
    {
        CircuitGate
        {
            typ: GateType::Zero,
            l,
            r,
            o,
            c: Vec::new()
        }
    }

    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    pub fn verify(&self, witness: &Vec<F>, next: &Self) -> bool
    {
        match self.typ
        {
            GateType::Zero => true,
            GateType::Generic => self.verify_generic(witness),
            GateType::Poseidon => self.verify_poseidon(witness, next),
            GateType::Add1 => self.verify_add1(witness, next),
            GateType::Add2 => self.verify_add2(witness),
            GateType::Vbmul1 => self.verify_vbmul1(witness, next),
            GateType::Vbmul2 => self.verify_vbmul2(witness, next),
            GateType::Vbmul3 => self.verify_vbmul3(witness, next),
        }
    }
}
