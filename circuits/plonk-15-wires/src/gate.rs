/*****************************************************************************************************************

This source file implements Plonk constraint gate primitive.

*****************************************************************************************************************/

use crate::{nolookup::constraints::ConstraintSystem, wires::*};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::FftField;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromPrimitive, ToPrimitive, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::OcamlEnum)
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitGate<F: FftField> {
    /// row position in the circuit
    // TODO(mimoo): shouldn't this be u32 since we serialize it as a u32?
    pub row: usize,
    /// type of the gate
    pub typ: GateType,
    /// gate wires
    pub wires: GateWires,
    /// constraints vector
    // TODO: rename
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
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
        }
    }
}

//
// Tests
//

#[cfg(any(test, feature = "testing"))]
mod tests {
    use super::*;
    use ark_ff::UniformRand as _;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;
    use rand::SeedableRng as _;

    // TODO: move to mina-curves
    prop_compose! {
        pub fn arb_fp()(seed: [u8; 32]) -> Fp {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            Fp::rand(rng)
        }
    }

    prop_compose! {
        fn arb_fp_vec(max: usize)(seed: [u8; 32], num in 0..max) -> Vec<Fp> {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            let mut v = vec![];
            for _ in 0..num {
                v.push(Fp::rand(rng))
            }
            v
        }
    }

    prop_compose! {
        fn arb_circuit_gate()(row in any::<usize>(), typ: GateType, wires: GateWires, c in arb_fp_vec(25)) -> CircuitGate<Fp> {
            CircuitGate {
                row,
                typ,
                wires,
                c,
            }
        }
    }

    proptest! {
        #[test]
        fn test_gate_serialization(cg in arb_circuit_gate()) {
            let encoded = bincode::serialize(&cg).unwrap();
            println!("gate: {:?}", cg);
            println!("encoded gate: {:?}", encoded);
            let decoded: CircuitGate<Fp> = bincode::deserialize(&encoded).unwrap();
            println!("decoded gate: {:?}", decoded);
            prop_assert_eq!(cg.row, decoded.row);
            prop_assert_eq!(cg.typ, decoded.typ);
            for i in 0..COLUMNS {
                prop_assert_eq!(cg.wires[i], decoded.wires[i]);
            }
            prop_assert_eq!(cg.c, decoded.c);
        }
    }
}
