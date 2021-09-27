/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use crate::{nolookup::constraints::ConstraintSystem, wires::*};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::FftField;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CurrOrNext {
    Curr,
    Next,
}

#[repr(C)]
#[derive(Clone, Eq, Hash, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive, PartialOrd, Ord)]
pub enum GateType {
    /// zero gate
    Zero,
    /// generic arithmetic gate
    Generic,
    /// Poseidon permutation gate
    Poseidon,
    /// EC addition in Affine form
    Add,
    /// EC point doubling in Affine form
    Double,
    /// EC variable base scalar multiplication
    Vbmul,
    /// EC variable base scalar multiplication with group endomorphim optimization
    Endomul,
    /// lookup
    Lookup,
    /// ChaCha
    ChaCha0,
    ChaCha1,
    ChaCha2,
    ChaChaFinal,
}

#[derive(Clone, Debug)]
pub struct CircuitGate<F: FftField> {
    /// row position in the circuit
    // TODO(mimoo): shouldn't this be u32 since we serialize it as a u32?
    pub row: usize,
    /// type of the gate
    pub typ: GateType,
    /// gate wires
    pub wires: GateWires,
    /// constraints vector
    pub c: Vec<F>,
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
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
            Wire::read(&mut r)?,
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
    /// this function creates "empty" circuit gate
    pub fn zero(row: usize, wires: GateWires) -> Self {
        CircuitGate {
            row,
            typ: GateType::Zero,
            c: Vec::new(),
            wires,
        }
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    pub fn verify(
        &self,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        match self.typ {
            GateType::Zero => Ok(()),
            GateType::Generic => self.verify_generic(witness),
            GateType::Poseidon => self.verify_poseidon(witness, cs),
            GateType::Add => self.verify_add(witness),
            GateType::Double => self.verify_double(witness),
            GateType::Vbmul => self.verify_vbmul(witness),
            GateType::Endomul => self.verify_endomul(witness, cs),
            GateType::Lookup => self.verify_lookup(witness),
            GateType::ChaCha0 | GateType::ChaCha1 | GateType::ChaCha2 | GateType::ChaChaFinal =>
                panic!("ChaCha verify not implement"),
        }
    }
}
