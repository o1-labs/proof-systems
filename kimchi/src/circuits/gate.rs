//! This module implements Plonk constraint gate primitive.

use crate::circuits::{constraints::ConstraintSystem, wires::*};
use ark_ff::FftField;
use ark_ff::{bytes::ToBytes, SquareRootField};
use num_traits::cast::ToPrimitive;
use o1_utils::hasher::CryptoDigest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::io::{Result as IoResult, Write};

/// A row accessible from a given row, corresponds to the fact that we open all polynomials
/// at `zeta` **and** `omega * zeta`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum CurrOrNext {
    Curr,
    Next,
}

impl CurrOrNext {
    /// Compute the offset corresponding to the `CurrOrNext` value.
    /// - `Curr.shift() == 0`
    /// - `Next.shift() == 1`
    pub fn shift(&self) -> usize {
        match self {
            CurrOrNext::Curr => 0,
            CurrOrNext::Next => 1,
        }
    }
}

/// The different types of gates the system supports.
/// Note that all the gates are mutually exclusive:
/// they cannot be used at the same time on single row.
/// If we were ever to support this feature, we would have to make sure
/// not to re-use powers of alpha across constraints.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum GateType {
    /// Zero gate
    Zero = 0,
    /// Generic arithmetic gate
    Generic = 1,
    /// Poseidon permutation gate
    Poseidon = 2,
    /// Complete EC addition in Affine form
    CompleteAdd = 3,
    /// EC variable base scalar multiplication
    VarBaseMul = 4,
    /// EC variable base scalar multiplication with group endomorphim optimization
    EndoMul = 5,
    /// Gate for computing the scalar corresponding to an endoscaling
    EndoMulScalar = 6,
    /// ChaCha
    ChaCha0 = 7,
    ChaCha1 = 8,
    ChaCha2 = 9,
    ChaChaFinal = 10,
    // Lookup
    Lookup = 11,
    /// Cairo
    CairoClaim = 12,
    CairoInstruction = 13,
    CairoFlags = 14,
    CairoTransition = 15,
    // Range check (16-24)
    RangeCheck0 = 16,
    RangeCheck1 = 17,
    RangeCheck2 = 18,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A single gate in a circuit.
pub struct CircuitGate<F: FftField> {
    /// type of the gate
    pub typ: GateType,
    /// gate wiring (for each cell, what cell it is wired to)
    pub wires: GateWires,
    /// public selector polynomials that can used as handy coefficients in gates
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub coeffs: Vec<F>,
}

impl<F: FftField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?
        }

        (self.coeffs.len() as u8).write(&mut w)?;
        for x in self.coeffs.iter() {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: FftField + SquareRootField> CircuitGate<F> {
    /// this function creates "empty" circuit gate
    pub fn zero(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::Zero,
            wires,
            coeffs: Vec::new(),
        }
    }

    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    pub fn verify(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
        public: &[F],
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            Generic => self.verify_generic(row, witness, public),
            Poseidon => self.verify_poseidon(row, witness, cs),
            CompleteAdd => self.verify_complete_add(row, witness),
            VarBaseMul => self.verify_vbmul(row, witness),
            EndoMul => self.verify_endomul(row, witness, cs),
            EndoMulScalar => self.verify_endomul_scalar(row, witness, cs),
            // TODO: implement the verification for chacha
            ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => Ok(()),
            // TODO: implement the verification for the lookup gate
            Lookup => Ok(()),
            CairoClaim | CairoInstruction | CairoFlags | CairoTransition => {
                self.verify_cairo_gate(row, witness, cs)
            }
            RangeCheck0 | RangeCheck1 | RangeCheck2 => self.verify_range_check(row, witness, cs),
        }
    }
}

/// A circuit is specified as a series of [CircuitGate].
#[derive(Serialize)]
pub struct Circuit<'a, F: FftField>(
    #[serde(bound = "CircuitGate<F>: Serialize")] pub &'a [CircuitGate<F>],
);

impl<'a, F: FftField> CryptoDigest for Circuit<'a, F> {
    const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::circuits::wires::caml::CamlWire;
    use itertools::Itertools;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlCircuitGate<F> {
        pub typ: GateType,
        pub wires: (
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
        ),
        pub coeffs: Vec<F>,
    }

    impl<F, CamlF> From<CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: FftField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Self {
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.into_iter().map(Into::into).collect(),
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
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.clone().into_iter().map(Into::into).collect(),
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
                typ: ccg.typ,
                wires: tuple_to_array(ccg.wires),
                coeffs: ccg.coeffs.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// helper to convert array to tuple (OCaml doesn't have fixed-size arrays)
    fn array_to_tuple<T1, T2>(a: [T1; PERMUTS]) -> (T2, T2, T2, T2, T2, T2, T2)
    where
        T1: Clone,
        T2: From<T1>,
    {
        a.into_iter()
            .map(Into::into)
            .next_tuple()
            .expect("bug in array_to_tuple")
    }

    /// helper to convert tuple to array (OCaml doesn't have fixed-size arrays)
    fn tuple_to_array<T1, T2>(a: (T1, T1, T1, T1, T1, T1, T1)) -> [T2; PERMUTS]
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
        ]
    }
}

//
// Tests
//

#[cfg(test)]
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
        fn arb_circuit_gate()(typ: GateType, wires: GateWires, coeffs in arb_fp_vec(25)) -> CircuitGate<Fp> {
            CircuitGate {
                typ,
                wires,
                coeffs,
            }
        }
    }

    proptest! {
        #[test]
        fn test_gate_serialization(cg in arb_circuit_gate()) {
            let encoded = rmp_serde::to_vec(&cg).unwrap();
            let decoded: CircuitGate<Fp> = rmp_serde::from_slice(&encoded).unwrap();
            prop_assert_eq!(cg.typ, decoded.typ);
            for i in 0..PERMUTS {
                prop_assert_eq!(cg.wires[i], decoded.wires[i]);
            }
            prop_assert_eq!(cg.coeffs, decoded.coeffs);
        }
    }
}
