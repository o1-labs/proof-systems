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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CurrOrNext {
    Curr,
    Next,
}

impl CurrOrNext {
    pub fn shift(&self) -> usize {
        match self {
            CurrOrNext::Curr => 0,
            CurrOrNext::Next => 1,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
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
    /// ChaCha
    ChaCha0,
    ChaCha1,
    ChaCha2,
    ChaChaFinal,
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
            GateType::ChaCha0 | GateType::ChaCha1 | GateType::ChaCha2 | GateType::ChaChaFinal =>
                panic!("ChaCha verify not implement"),
        }
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::wires::caml::CamlWire;
    use ocaml_gen::OcamlGen;
    use std::convert::TryInto;

    #[derive(ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlCircuitGate<F> {
        pub row: ocaml::Int,
        pub typ: GateType,
        pub wires: (
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
        ),
        pub c: Vec<F>,
    }

    impl<F, CamlF> From<CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Self {
                row: cg.row.try_into().expect("usize -> isize"),
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                c: cg.c.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<&CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: &CircuitGate<F>) -> Self {
            Self {
                row: cg.row.try_into().expect("usize -> isize"),
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                c: cg.c.clone().into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlCircuitGate<CamlF>> for CircuitGate<F>
    where
        F: From<CamlF>,
        F: FftField,
    {
        fn from(ccg: CamlCircuitGate<CamlF>) -> Self {
            Self {
                row: ccg.row.try_into().expect("isize -> usize"),
                typ: ccg.typ,
                wires: tuple_to_array(ccg.wires),
                c: ccg.c.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// helper to convert array to tuple (OCaml doesn't have fixed-size arrays)
    fn array_to_tuple<T1, T2>(
        a: [T1; 15],
    ) -> (T2, T2, T2, T2, T2, T2, T2, T2, T2, T2, T2, T2, T2, T2, T2)
    where
        T1: Clone,
        T2: From<T1>,
    {
        (
            a[0].clone().into(),
            a[1].clone().into(),
            a[2].clone().into(),
            a[3].clone().into(),
            a[4].clone().into(),
            a[5].clone().into(),
            a[6].clone().into(),
            a[7].clone().into(),
            a[8].clone().into(),
            a[9].clone().into(),
            a[10].clone().into(),
            a[11].clone().into(),
            a[12].clone().into(),
            a[13].clone().into(),
            a[14].clone().into(),
        )
    }

    /// helper to convert tuple to array (OCaml doesn't have fixed-size arrays)
    fn tuple_to_array<T1, T2>(
        a: (T1, T1, T1, T1, T1, T1, T1, T1, T1, T1, T1, T1, T1, T1, T1),
    ) -> [T2; 15]
    where
        T2: From<T1>,
    {
        [
            a.0.into(),
            a.1.into(),
            a.2.into(),
            a.3.into(),
            a.4.into(),
            a.5.into(),
            a.6.into(),
            a.7.into(),
            a.8.into(),
            a.9.into(),
            a.10.into(),
            a.11.into(),
            a.12.into(),
            a.13.into(),
            a.14.into(),
        ]
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
