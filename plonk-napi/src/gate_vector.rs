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
            #[napi(object)]
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

                    Self {
                        typ: gate_type_to_i32(value.typ),
                        wires: (&value.wires).into(),
                        coeffs,
                    }
                }
            }

            #[napi]
            #[derive(Clone, Default, Debug)]
            pub struct [<Napi $field_name:camel GateVector>](
                #[napi(skip)] pub Vec<CircuitGate<$F>>,
            );

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_create>]() -> [<Napi $field_name:camel GateVector>] {
                println!("from native rust creating gate vector");
                [<Napi $field_name:camel GateVector>](Vec::new())
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_add>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                gate: [<Napi $field_name:camel Gate>],
            ) -> Result<()> {
                println!("from native rust adding gate to vector");
                vector.0.push(gate.into_inner()?);
                Ok(())
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_get>](
                vector: &[<Napi $field_name:camel GateVector>],
                index: i32,
            ) -> [<Napi $field_name:camel Gate>] {
                println!("from native rust getting gate from vector");
                [<Napi $field_name:camel Gate>]::from_inner(&vector.0[index as usize])
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_len>](
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> i32 {
                println!("from native rust getting gate vector length");
                vector.0.len() as i32
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_wrap>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                target: NapiWire,
                head: NapiWire,
            ) {
                println!("from native rust wrapping wire in gate vector");
                vector.0[target.row as usize].wires[target.col as usize] = KimchiWire::from(head);
              }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_digest>](
                public_input_size: i32,
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Uint8Array {
                println!("from native rust computing gate vector digest");
                let bytes = Circuit::new(public_input_size as usize, &vector.0)
                    .digest()
                    .to_vec();
                Uint8Array::from(bytes)
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_circuit_serialize>](
                public_input_size: i32,
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Result<String> {
                println!("from native rust serializing gate vector to json");
                let circuit = Circuit::new(public_input_size as usize, &vector.0);
                serde_json::to_string(&circuit).map_err(|err| {
                    Error::new(
                        Status::GenericFailure,
                        format!("couldn't serialize constraints: {}", err),
                    )
                })
            }
        }
    };
}

impl_gate_support!(fp, Fp, WasmPastaFp);
impl_gate_support!(fq, Fq, WasmPastaFq);
