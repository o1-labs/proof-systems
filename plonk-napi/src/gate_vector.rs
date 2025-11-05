use ark_ff::PrimeField;
use kimchi::circuits::{
    gate::{Circuit, CircuitGate, GateType},
    wires::Wire,
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use o1_utils::hasher::CryptoDigest;
use paste::paste;
use std::ops::Deref;
use wasm_types::{FlatVector as WasmFlatVector, FlatVectorElem};

use crate::wrappers::{
    field::{NapiPastaFp, NapiPastaFq},
    wires::NapiWire,
};

pub mod shared {
    use super::*;

    /// Number of wires stored per gate.
    pub const WIRE_COUNT: usize = 7;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GateWires(pub [Wire; WIRE_COUNT]);

    impl GateWires {
        pub fn new(wires: [Wire; WIRE_COUNT]) -> Self {
            Self(wires)
        }

        pub fn as_array(&self) -> &[Wire; WIRE_COUNT] {
            &self.0
        }

        pub fn into_array(self) -> [Wire; WIRE_COUNT] {
            self.0
        }
    }

    impl From<[Wire; WIRE_COUNT]> for GateWires {
        fn from(wires: [Wire; WIRE_COUNT]) -> Self {
            GateWires::new(wires)
        }
    }

    impl From<GateWires> for [Wire; WIRE_COUNT] {
        fn from(gw: GateWires) -> Self {
            gw.into_array()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Gate<F: PrimeField> {
        pub typ: GateType,
        pub wires: GateWires,
        pub coeffs: Vec<F>,
    }

    impl<F> From<CircuitGate<F>> for Gate<F>
    where
        F: PrimeField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Gate {
                typ: cg.typ,
                wires: GateWires::new([
                    cg.wires[0],
                    cg.wires[1],
                    cg.wires[2],
                    cg.wires[3],
                    cg.wires[4],
                    cg.wires[5],
                    cg.wires[6],
                ]),
                coeffs: cg.coeffs,
            }
        }
    }

    impl<F> From<&CircuitGate<F>> for Gate<F>
    where
        F: PrimeField,
    {
        fn from(cg: &CircuitGate<F>) -> Self {
            Gate {
                typ: cg.typ,
                wires: GateWires::new([
                    cg.wires[0],
                    cg.wires[1],
                    cg.wires[2],
                    cg.wires[3],
                    cg.wires[4],
                    cg.wires[5],
                    cg.wires[6],
                ]),
                coeffs: cg.coeffs.clone(),
            }
        }
    }

    impl<F> From<Gate<F>> for CircuitGate<F>
    where
        F: PrimeField,
    {
        fn from(gate: Gate<F>) -> Self {
            CircuitGate {
                typ: gate.typ,
                wires: gate.wires.into_array(),
                coeffs: gate.coeffs,
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct GateVector<F: PrimeField> {
        gates: Vec<CircuitGate<F>>,
    }

    impl<F> GateVector<F>
    where
        F: PrimeField,
    {
        pub fn new() -> Self {
            Self { gates: Vec::new() }
        }

        pub fn from_vec(gates: Vec<CircuitGate<F>>) -> Self {
            Self { gates }
        }

        pub fn into_inner(self) -> Vec<CircuitGate<F>> {
            self.gates
        }

        pub fn as_slice(&self) -> &[CircuitGate<F>] {
            &self.gates
        }

        pub fn iter(&self) -> core::slice::Iter<'_, CircuitGate<F>> {
            self.gates.iter()
        }

        pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, CircuitGate<F>> {
            self.gates.iter_mut()
        }

        pub fn push_gate(&mut self, gate: CircuitGate<F>) {
            self.gates.push(gate);
        }

        pub fn len(&self) -> usize {
            self.gates.len()
        }

        pub fn get_gate(&self, index: usize) -> Option<Gate<F>> {
            self.gates.get(index).map(Gate::from)
        }

        pub fn wrap_wire(&mut self, target: Wire, replacement: Wire) {
            if let Some(gate) = self.gates.get_mut(target.row) {
                if target.col < gate.wires.len() {
                    gate.wires[target.col] = replacement;
                }
            }
        }

        pub fn digest(&self, public_input_size: usize) -> Vec<u8> {
            Circuit::new(public_input_size, self.as_slice())
                .digest()
                .to_vec()
        }

        pub fn serialize(
            &self,
            public_input_size: usize,
        ) -> std::result::Result<String, serde_json::Error> {
            let circuit = Circuit::new(public_input_size, self.as_slice());
            serde_json::to_string(&circuit)
        }
    }

    impl<F> From<Vec<CircuitGate<F>>> for GateVector<F>
    where
        F: PrimeField,
    {
        fn from(gates: Vec<CircuitGate<F>>) -> Self {
            GateVector::from_vec(gates)
        }
    }

    impl<F> From<GateVector<F>> for Vec<CircuitGate<F>>
    where
        F: PrimeField,
    {
        fn from(vec: GateVector<F>) -> Self {
            vec.into_inner()
        }
    }
}

pub use self::shared::{GateVector as CoreGateVector, GateWires as CoreGateWires};

fn gate_vector_error(context: &str, err: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, format!("{}: {}", context, err))
}

#[napi(object, js_name = "WasmGateWires")]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiGateWires {
    pub w0: NapiWire,
    pub w1: NapiWire,
    pub w2: NapiWire,
    pub w3: NapiWire,
    pub w4: NapiWire,
    pub w5: NapiWire,
    pub w6: NapiWire,
}

impl From<CoreGateWires> for NapiGateWires {
    fn from(wires: CoreGateWires) -> Self {
        let array = wires.into_array();
        NapiGateWires {
            w0: array[0].into(),
            w1: array[1].into(),
            w2: array[2].into(),
            w3: array[3].into(),
            w4: array[4].into(),
            w5: array[5].into(),
            w6: array[6].into(),
        }
    }
}

impl From<NapiGateWires> for CoreGateWires {
    fn from(wires: NapiGateWires) -> Self {
        CoreGateWires::new(wires.into_inner())
    }
}

impl NapiGateWires {
    fn into_inner(self) -> [Wire; shared::WIRE_COUNT] {
        [
            self.w0.into(),
            self.w1.into(),
            self.w2.into(),
            self.w3.into(),
            self.w4.into(),
            self.w5.into(),
            self.w6.into(),
        ]
    }
}

fn gate_type_from_i32(value: i32) -> Result<GateType> {
    // Ocaml/JS int are signed, so we use i32 here
    if value < 0 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("invalid GateType discriminant: {}", value),
        ));
    }

    let variants: &[GateType] = &[
        GateType::Zero,
        GateType::Generic,
        GateType::Poseidon,
        GateType::CompleteAdd,
        GateType::VarBaseMul,
        GateType::EndoMul,
        GateType::EndoMulScalar,
        GateType::Lookup,
        GateType::CairoClaim,
        GateType::CairoInstruction,
        GateType::CairoFlags,
        GateType::CairoTransition,
        GateType::RangeCheck0,
        GateType::RangeCheck1,
        GateType::ForeignFieldAdd,
        GateType::ForeignFieldMul,
        GateType::Xor16,
        GateType::Rot64,
    ];

    let index = value as usize;
    variants.get(index).copied().ok_or_else(|| {
        Error::new(
            Status::InvalidArg,
            format!("invalid GateType discriminant: {}", value),
        )
    })
}

// For convenience to not expose the GateType enum to JS
fn gate_type_to_i32(value: GateType) -> i32 {
    value as i32
}

macro_rules! impl_gate_support {
    ($field_name:ident, $F:ty, $WasmF:ty) => {
        paste! {
            #[napi(object, js_name = [<"Wasm" $field_name:camel "Gate">])]
            #[derive(Clone, Debug, Default)]
            pub struct [<Napi $field_name:camel Gate>] {
                pub typ: i32, // for convenience, we use i32 instead of GateType
                pub wires: NapiGateWires,
                pub coeffs: Vec<u8>, // for now, serializing fields as flat bytes, but subject to changes
            }

            impl [<Napi $field_name:camel Gate>] {
                fn into_inner(self) -> Result<CircuitGate<$F>> {
                    let coeffs = WasmFlatVector::<$WasmF>::from_bytes(self.coeffs)
                        .into_iter()
                        .map(Into::into)
                        .collect();

                    Ok(CircuitGate {
                        typ: gate_type_from_i32(self.typ)?,
                        wires: self.wires.into_inner(),
                        coeffs,
                    })
                }

                fn from_inner(value: &CircuitGate<$F>) -> Self {
                    let coeffs = value
                        .coeffs
                        .iter()
                        .cloned()
                        .map($WasmF::from)
                        .flat_map(|elem| elem.flatten())
                        .collect();

                    let wires = CoreGateWires::new([
                        value.wires[0],
                        value.wires[1],
                        value.wires[2],
                        value.wires[3],
                        value.wires[4],
                        value.wires[5],
                        value.wires[6],
                    ]);

                    Self {
                        typ: gate_type_to_i32(value.typ),
                        wires: wires.into(),
                        coeffs,
                    }
                }
            }

            #[napi(js_name = [<"Wasm" $field_name:camel "GateVector">])]
            #[derive(Clone, Debug, Default)]
            pub struct [<Napi $field_name:camel GateVector>](
                #[napi(skip)] pub CoreGateVector<$F>,
            );

            impl Deref for [<Napi $field_name:camel GateVector>] {
                type Target = CoreGateVector<$F>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl From<CoreGateVector<$F>> for [<Napi $field_name:camel GateVector>] {
                fn from(inner: CoreGateVector<$F>) -> Self {
                    Self(inner)
                }
            }

            impl From<[<Napi $field_name:camel GateVector>]> for CoreGateVector<$F> {
                fn from(vector: [<Napi $field_name:camel GateVector>]) -> Self {
                    vector.0
                }
            }

            #[napi]
            impl [<Napi $field_name:camel GateVector>] {
                #[napi(constructor)]
                pub fn new() -> Self {
                    CoreGateVector::new().into()
                }

                #[napi]
                pub fn serialize(&self) -> Result<Uint8Array> {
                    let bytes = rmp_serde::to_vec(self.0.as_slice())
                        .map_err(|e| gate_vector_error("gate vector serialize failed", e))?;
                    Ok(Uint8Array::from(bytes))
                }

                #[napi(factory)]
                pub fn deserialize(bytes: Uint8Array) -> Result<Self> {
                    let gates: Vec<CircuitGate<$F>> = rmp_serde::from_slice(bytes.as_ref())
                        .map_err(|e| gate_vector_error("gate vector deserialize failed", e))?;
                    Ok(CoreGateVector::from_vec(gates).into())
                }

                pub(crate) fn inner(&self) -> &CoreGateVector<$F> {
                    &self.0
                }

                pub(crate) fn inner_mut(&mut self) -> &mut CoreGateVector<$F> {
                    &mut self.0
                }

                pub(crate) fn as_slice(&self) -> &[CircuitGate<$F>] {
                    self.0.as_slice()
                }

                pub(crate) fn to_vec(&self) -> Vec<CircuitGate<$F>> {
                    self.0.as_slice().to_vec()
                }
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_create">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_create>]() -> [<Napi $field_name:camel GateVector>] {
                [<Napi $field_name:camel GateVector>]::new()
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_add">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_add>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                gate: [<Napi $field_name:camel Gate>],
            ) -> Result<()> {
                let gate = gate.into_inner()?;
                vector.inner_mut().push_gate(gate);
                Ok(())
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_get">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_get>](
                vector: &[<Napi $field_name:camel GateVector>],
                index: i32,
            ) -> [<Napi $field_name:camel Gate>] {
                let gate = vector
                    .as_slice()
                    .get(index as usize)
                    .expect("index out of bounds");
                [<Napi $field_name:camel Gate>]::from_inner(gate)
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_len">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_len>](
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> i32 {
                vector.as_slice().len() as i32
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_wrap">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_wrap>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                target: NapiWire,
                head: NapiWire,
            ) {
                let target: Wire = target.into();
                let head: Wire = head.into();
                vector.inner_mut().wrap_wire(target, head);
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_digest">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_digest>](
                public_input_size: i32,
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Uint8Array {
                let bytes = vector.inner().digest(public_input_size as usize);
                Uint8Array::from(bytes)
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_circuit_serialize">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_circuit_serialize>](
                public_input_size: i32,
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Result<String> {
                vector
                    .inner()
                    .serialize(public_input_size as usize)
                    .map_err(|err| {
                        Error::new(
                            Status::GenericFailure,
                            format!("couldn't serialize constraints: {}", err),
                        )
                    })
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_to_bytes">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_to_bytes>](
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Result<Uint8Array> {
                vector.serialize()
            }

            #[napi(js_name = [<"caml_pasta_" $field_name:snake "_plonk_gate_vector_from_bytes">])]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_from_bytes>](
                bytes: Uint8Array,
            ) -> Result<[<Napi $field_name:camel GateVector>]> {
                [<Napi $field_name:camel GateVector>]::deserialize(bytes)
            }
        }
    };
}

impl_gate_support!(fp, Fp, NapiPastaFp);
impl_gate_support!(fq, Fq, NapiPastaFq);
