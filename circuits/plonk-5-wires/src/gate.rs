/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use algebra::FftField;
pub use super::{wires::{*}, constraints::ConstraintSystem};
use std::io::{Read, Result as IoResult, Write, Error, ErrorKind};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use algebra::bytes::{FromBytes, ToBytes};
use crate::gates::{zero::ZeroGateType, generic::GenericGateType, poseidon::PoseidonGateType, addition::AddGateType, double::DoubleGateType, varbasemul::VbmulGateType, varbasemulpck::VbmulpackGateType, endosclmul::EndomulGateType, packing::PackGateType};

#[repr(C)]
#[derive(Clone, Debug)]
#[derive(PartialEq)]
#[derive(FromPrimitive, ToPrimitive)]
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

impl ZeroGateType for GateType {
    const ZERO: Self = GateType::Zero;
}

impl GenericGateType for GateType {
    const GENERIC: Self = GateType::Generic;
}

impl PoseidonGateType for GateType {
    const POSEIDON: Self = GateType::Poseidon;
}

impl AddGateType for GateType {
    const ADD: Self = GateType::Add;
}

impl DoubleGateType for GateType {
    const DOUBLE: Self = GateType::Double;
}

impl VbmulGateType for GateType {
    const VBMUL1: Self = GateType::Vbmul1;
}

impl VbmulpackGateType for GateType {
    const VBMUL2: Self = GateType::Vbmul2;
}

impl EndomulGateType for GateType {
    const ENDOMUL: Self = GateType::Endomul;
}

impl PackGateType for GateType {
    const PACK: Self = GateType::Pack;
}

#[derive(Clone)]
pub struct CircuitGate<F: FftField, GateType>
{
    pub row: usize,         // row position in the circuit
    pub typ: GateType,      // type of the gate
    pub wires: GateWires,   // gate wires
    pub c: Vec<F>,          // constraints vector
}

impl<F: FftField, GateType: ToPrimitive> ToBytes for CircuitGate<F, GateType> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        (self.row as u32).write(&mut w)?;
        let typ : u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {self.wires[i].write(&mut w)?};

        (self.c.len() as u8).write(&mut w)?;
        for x in self.c.iter() {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: FftField, GateType: FromPrimitive> FromBytes for CircuitGate<F, GateType> {
    #[inline]
    fn read<R: Read>(mut r: R) -> IoResult<Self> {
        let row = u32::read(&mut r)? as usize;
        let code = u8::read(&mut r)?;
        let typ =
            match FromPrimitive::from_u8(code) {
                Some(x) => Ok(x),
                None => Err(Error::new(ErrorKind::Other, "Invalid gate type"))
            }?;

        let wires =
        [
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
        ];

        let c_len = u8::read(&mut r)?;
        let mut c = vec![];
        for _ in 0..c_len {
            c.push(F::read(&mut r)?);
        }

        Ok(CircuitGate {
            row,
            typ,
            wires,
            c
        })
    }
}

impl<F: FftField> CircuitGate<F, GateType>
{
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
