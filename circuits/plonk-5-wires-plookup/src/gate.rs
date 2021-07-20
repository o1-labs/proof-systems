/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

pub use super::{constraints::ConstraintSystem, wires::*};
use algebra::bytes::{FromBytes, ToBytes};
use algebra::FftField;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum GateType {
    Zero,     // zero gate
    Generic,  // generic arithmetic gate
    Poseidon, // Poseidon permutation gate
    Add,      // EC addition in Affine form
    Double,   // EC point doubling in Affine form
    Vbmul1,   // EC variable base scalar multiplication
    Vbmul2,   // unpacking EC variable base scalar multiplication
    Endomul,  // EC variable base scalar multiplication with group endomorphim optimization
    Pack,     // packing
    Lookup,   // lookup
}

#[derive(Clone)]
pub struct CircuitGate<F: FftField> {
    pub row: usize,       // row position in the circuit
    pub typ: GateType,    // type of the gate
    pub wires: GateWires, // gate wires
    pub c: Vec<F>,        // constraints vector
}

impl<F: FftField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        (self.row as u32).write(&mut w)?;
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?
        }

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
        let row = u32::read(&mut r)? as usize;
        let code = u8::read(&mut r)?;
        let typ = match FromPrimitive::from_u8(code) {
            Some(x) => Ok(x),
            None => Err(Error::new(ErrorKind::Other, "Invalid gate type")),
        }?;

        let wires = [
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

        Ok(CircuitGate { row, typ, wires, c })
    }
}

impl<F: FftField> CircuitGate<F> {
    // this function creates "empty" circuit gate
    pub fn zero(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Zero,
            c: Vec::new(),
            wires,
        }
    }

    // This function verifies the consistency of the wire
    // assignements (witness) against the constraints
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS], cs: &ConstraintSystem<F>) -> bool {
        match self.typ {
            GateType::Zero => true,
            GateType::Generic => self.verify_generic(witness),
            GateType::Poseidon => self.verify_poseidon(witness, cs),
            GateType::Add => self.verify_add(witness),
            GateType::Double => self.verify_double(witness),
            GateType::Vbmul1 => self.verify_vbmul1(witness),
            GateType::Vbmul2 => self.verify_vbmul2(witness),
            GateType::Endomul => self.verify_endomul(witness, cs),
            GateType::Pack => self.verify_pack(witness),
            GateType::Lookup => self.verify_lookup(witness),
        }
    }
}
