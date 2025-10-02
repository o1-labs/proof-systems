use kimchi::circuits::{
    gate::{Circuit, CircuitGate, GateType},
    wires::{GateWires, Wire as KimchiWire},
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use o1_utils::hasher::CryptoDigest;
use paste::paste;
use wasm_types::{FlatVector as WasmFlatVector, FlatVectorElem};

use crate::wrappers::{
    field::{WasmPastaFp, WasmPastaFq},
    wires::NapiWire,
};

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NapiGateWires {
    pub w0: NapiWire,
    pub w1: NapiWire,
    pub w2: NapiWire,
    pub w3: NapiWire,
    pub w4: NapiWire,
    pub w5: NapiWire,
    pub w6: NapiWire,
}

impl NapiGateWires {
    fn into_inner(self) -> GateWires {
        [
            KimchiWire::from(self.w0),
            KimchiWire::from(self.w1),
            KimchiWire::from(self.w2),
            KimchiWire::from(self.w3),
            KimchiWire::from(self.w4),
            KimchiWire::from(self.w5),
            KimchiWire::from(self.w6),
        ]
    }
}

impl From<&GateWires> for NapiGateWires {
    fn from(value: &GateWires) -> Self {
        Self {
            w0: value[0].into(),
            w1: value[1].into(),
            w2: value[2].into(),
            w3: value[3].into(),
            w4: value[4].into(),
            w5: value[5].into(),
            w6: value[6].into(),
        }
    }
}

fn gate_type_from_i32(value: i32) -> Result<GateType> {
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

fn gate_type_to_i32(value: GateType) -> i32 {
    value as i32
}

macro_rules! impl_gate_support {
    ($module:ident, $field:ty, $wasm_field:ty) => {
        paste! {
            #[napi(object)]
            #[derive(Clone, Debug, Default)]
            pub struct [<Napi $module:camel Gate>] {
                pub typ: i32,
                pub wires: NapiGateWires,
                pub coeffs: Vec<u8>,
            }

            impl [<Napi $module:camel Gate>] {
                fn into_inner(self) -> Result<CircuitGate<$field>> {
                    let coeffs = WasmFlatVector::<$wasm_field>::from_bytes(self.coeffs)
                        .into_iter()
                        .map(Into::into)
                        .collect();

                    Ok(CircuitGate {
                        typ: gate_type_from_i32(self.typ)?,
                        wires: self.wires.into_inner(),
                        coeffs,
                    })
                }

                fn from_inner(value: &CircuitGate<$field>) -> Self {
                    let coeffs = value
                        .coeffs
                        .iter()
                        .cloned()
                        .map($wasm_field::from)
                        .flat_map(|elem| elem.flatten())
                        .collect();

                    Self {
                        typ: gate_type_to_i32(value.typ),
                        wires: (&value.wires).into(),
                        coeffs,
                    }
                }
            }

            #[napi]
            #[derive(Clone, Default, Debug)]
            pub struct [<Napi $module:camel GateVector>] {
                #[napi(skip)]
                pub inner: Vec<CircuitGate<$field>>,
            }

            #[napi]
            impl [<Napi $module:camel GateVector>] {
                #[napi(constructor)]
                pub fn new() -> Self {
                    Self { inner: Vec::new() }
                }

                #[napi]
                pub fn add(&mut self, gate: [<Napi $module:camel Gate>]) -> Result<()> {
                    self.inner.push(gate.into_inner()?);
                    Ok(())
                }

                #[napi]
                pub fn get(&self, index: i32) -> [<Napi $module:camel Gate>] {
                    [<Napi $module:camel Gate>]::from_inner(&self.inner[index as usize])
                }

                #[napi]
                pub fn len(&self) -> i32 {
                    self.inner.len() as i32
                }

                #[napi]
                pub fn wrap(&mut self, target: NapiWire, head: NapiWire) {
                    let row = target.row as usize;
                    let col = target.col as usize;
                    self.inner[row].wires[col] = KimchiWire::from(head);
                }

                #[napi]
                pub fn digest(&self, public_input_size: i32) -> Vec<u8> {
                    Circuit::new(public_input_size as usize, &self.inner)
                        .digest()
                        .to_vec()
                }

                #[napi]
                pub fn serialize(&self, public_input_size: i32) -> Result<String> {
                    let circuit = Circuit::new(public_input_size as usize, &self.inner);
                    serde_json::to_string(&circuit).map_err(|err| {
                        Error::new(
                            Status::GenericFailure,
                            format!("failed to serialize circuit: {}", err),
                        )
                    })
                }
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_create>]() -> [<Napi $module:camel GateVector>] {
                [<Napi $module:camel GateVector>]::new()
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_add>](
                vector: &mut [<Napi $module:camel GateVector>],
                gate: [<Napi $module:camel Gate>],
            ) -> Result<()> {
                vector.add(gate)
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_get>](
                vector: &[<Napi $module:camel GateVector>],
                index: i32,
            ) -> [<Napi $module:camel Gate>] {
                vector.get(index)
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_len>](
                vector: &[<Napi $module:camel GateVector>],
            ) -> i32 {
                vector.len()
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_wrap>](
                vector: &mut [<Napi $module:camel GateVector>],
                target: NapiWire,
                head: NapiWire,
            ) {
                vector.wrap(target, head);
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_gate_vector_digest>](
                public_input_size: i32,
                vector: &[<Napi $module:camel GateVector>],
            ) -> Vec<u8> {
                vector.digest(public_input_size)
            }

            #[napi]
            pub fn [<caml_pasta_ $module:snake _plonk_circuit_serialize>](
                public_input_size: i32,
                vector: &[<Napi $module:camel GateVector>],
            ) -> Result<String> {
                vector.serialize(public_input_size)
            }
        }
    };
}

impl_gate_support!(fp, Fp, WasmPastaFp);
impl_gate_support!(fq, Fq, WasmPastaFq);
