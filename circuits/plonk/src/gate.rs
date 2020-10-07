/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use algebra::FftField;
pub use super::{wires::{*}, constraints::ConstraintSystem};
use std::io::{Read, Result as IoResult, Write, Error, ErrorKind};
use algebra::bytes::{FromBytes, ToBytes};
use num_traits::cast::{FromPrimitive, ToPrimitive};

#[repr(C)]
#[derive(Clone, Debug)]
#[derive(PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
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


impl<F: FftField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        let typ : u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        self.wires.write(&mut w)?;

        (self.c.len() as u8).write(&mut w)?;
        for x in self.c.iter() {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: FftField> FromBytes for CircuitGate<F> {
    #[inline]
    fn read<R: Read>(mut r: R) -> IoResult<Self> {
        let code = u8::read(&mut r)?;
        let typ =
            match FromPrimitive::from_u8(code) {
                Some(x) => Ok(x),
                None => Err(Error::new(ErrorKind::Other, "Invalid gate type"))
            }?;

        let wires = GateWires::read(&mut r)?;

        let c_len = u8::read(&mut r)?;
        let mut c = vec![];
        for _ in 0..c_len {
            c.push(F::read(&mut r)?);
        }

        Ok(CircuitGate {
            typ,
            wires,
            c
        })
    }
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
            GateType::Poseidon  => self.verify_poseidon(next, witness, cs),
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

#[derive(Clone)]
pub struct Gate<F: FftField>
{
    pub typ: GateType,      // type of the gate
    pub wires: Wires,       // gate wires
    pub c: Vec<F>,          // constraints vector
}
