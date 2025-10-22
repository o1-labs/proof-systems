use std::convert::TryFrom;

use arkworks::{WasmPastaFp, WasmPastaFq};
use kimchi::circuits::{
    gate::{CircuitGate, GateType},
    wires::Wire,
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::{Error, External, Status, Uint8Array};
use napi_derive::napi;
use plonk_wasm::gate_vector::{
    CoreGate as Gate, CoreGateVector as GateVector, CoreGateWires as GateWires,
};
use wasm_types::{FlatVector, FlatVectorElem};

pub struct GateVectorHandleFp(pub GateVector<Fp>);
pub struct GateVectorHandleFq(pub GateVector<Fq>);

impl GateVectorHandleFp {
    fn new() -> Self {
        Self(GateVector::new())
    }
    pub(crate) fn inner(&self) -> &GateVector<Fp> {
        &self.0
    }
    pub(crate) fn inner_mut(&mut self) -> &mut GateVector<Fp> {
        &mut self.0
    }
}

impl GateVectorHandleFq {
    fn new() -> Self {
        Self(GateVector::new())
    }
    pub(crate) fn inner(&self) -> &GateVector<Fq> {
        &self.0
    }
    pub(crate) fn inner_mut(&mut self) -> &mut GateVector<Fq> {
        &mut self.0
    }
}

unsafe impl Send for GateVectorHandleFp {}
unsafe impl Sync for GateVectorHandleFp {}
unsafe impl Send for GateVectorHandleFq {}
unsafe impl Sync for GateVectorHandleFq {}

#[napi(object)]
pub struct JsWire {
    pub row: u32,
    pub col: u32,
}

#[napi(object)]
pub struct JsGateWires {
    pub w0: JsWire,
    pub w1: JsWire,
    pub w2: JsWire,
    pub w3: JsWire,
    pub w4: JsWire,
    pub w5: JsWire,
    pub w6: JsWire,
}

#[napi(object)]
pub struct JsGateFp {
    pub typ: i32,
    pub wires: JsGateWires,
    pub coeffs: Uint8Array,
}

#[napi(object)]
pub struct JsGateFq {
    pub typ: i32,
    pub wires: JsGateWires,
    pub coeffs: Uint8Array,
}

fn gate_type_from_i32(value: i32) -> napi::Result<GateType> {
    match value {
        0 => Ok(GateType::Zero),
        1 => Ok(GateType::Generic),
        2 => Ok(GateType::Poseidon),
        3 => Ok(GateType::CompleteAdd),
        4 => Ok(GateType::VarBaseMul),
        5 => Ok(GateType::EndoMul),
        6 => Ok(GateType::EndoMulScalar),
        7 => Ok(GateType::Lookup),
        8 => Ok(GateType::CairoClaim),
        9 => Ok(GateType::CairoInstruction),
        10 => Ok(GateType::CairoFlags),
        11 => Ok(GateType::CairoTransition),
        12 => Ok(GateType::RangeCheck0),
        13 => Ok(GateType::RangeCheck1),
        14 => Ok(GateType::ForeignFieldAdd),
        15 => Ok(GateType::ForeignFieldMul),
        16 => Ok(GateType::Xor16),
        17 => Ok(GateType::Rot64),
        _ => Err(Error::new(
            Status::InvalidArg,
            format!("unknown gate type discriminant {value}"),
        )),
    }
}

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

fn js_wire_to_wire(wire: &JsWire) -> napi::Result<Wire> {
    Ok(Wire {
        row: wire.row as usize,
        col: wire.col as usize,
    })
}

fn wire_to_js(wire: Wire) -> napi::Result<JsWire> {
    Ok(JsWire {
        row: u32::try_from(wire.row).map_err(|_| {
            Error::new(
                Status::InvalidArg,
                format!("wire row {row} does not fit in u32", row = wire.row),
            )
        })?,
        col: u32::try_from(wire.col).map_err(|_| {
            Error::new(
                Status::InvalidArg,
                format!("wire col {col} does not fit in u32", col = wire.col),
            )
        })?,
    })
}

fn js_wires_to_core(wires: &JsGateWires) -> napi::Result<GateWires> {
    Ok(GateWires::new([
        js_wire_to_wire(&wires.w0)?,
        js_wire_to_wire(&wires.w1)?,
        js_wire_to_wire(&wires.w2)?,
        js_wire_to_wire(&wires.w3)?,
        js_wire_to_wire(&wires.w4)?,
        js_wire_to_wire(&wires.w5)?,
        js_wire_to_wire(&wires.w6)?,
    ]))
}

fn core_wires_to_js(wires: &GateWires) -> napi::Result<JsGateWires> {
    let arr = wires.as_array();
    Ok(JsGateWires {
        w0: wire_to_js(arr[0])?,
        w1: wire_to_js(arr[1])?,
        w2: wire_to_js(arr[2])?,
        w3: wire_to_js(arr[3])?,
        w4: wire_to_js(arr[4])?,
        w5: wire_to_js(arr[5])?,
        w6: wire_to_js(arr[6])?,
    })
}

fn coeffs_from_bytes_fp(bytes: Vec<u8>) -> Vec<Fp> {
    FlatVector::<WasmPastaFp>::from_bytes(bytes)
        .into_iter()
        .map(Into::into)
        .collect()
}

fn coeffs_from_bytes_fq(bytes: Vec<u8>) -> Vec<Fq> {
    FlatVector::<WasmPastaFq>::from_bytes(bytes)
        .into_iter()
        .map(Into::into)
        .collect()
}

fn coeffs_to_bytes_fp(coeffs: &[Fp]) -> Vec<u8> {
    coeffs
        .iter()
        .cloned()
        .map(WasmPastaFp)
        .flat_map(FlatVectorElem::flatten)
        .collect()
}

fn coeffs_to_bytes_fq(coeffs: &[Fq]) -> Vec<u8> {
    coeffs
        .iter()
        .cloned()
        .map(WasmPastaFq)
        .flat_map(FlatVectorElem::flatten)
        .collect()
}

fn js_gate_fp_to_core(gate: JsGateFp) -> napi::Result<Gate<Fp>> {
    let typ = gate_type_from_i32(gate.typ)?;
    let wires = js_wires_to_core(&gate.wires)?;
    let coeff_bytes = gate.coeffs.to_vec();
    Ok(Gate {
        typ,
        wires,
        coeffs: coeffs_from_bytes_fp(coeff_bytes),
    })
}

fn js_gate_fq_to_core(gate: JsGateFq) -> napi::Result<Gate<Fq>> {
    let typ = gate_type_from_i32(gate.typ)?;
    let wires = js_wires_to_core(&gate.wires)?;
    let coeff_bytes = gate.coeffs.to_vec();
    Ok(Gate {
        typ,
        wires,
        coeffs: coeffs_from_bytes_fq(coeff_bytes),
    })
}

fn core_gate_fp_to_js(gate: Gate<Fp>) -> napi::Result<JsGateFp> {
    let coeff_bytes = coeffs_to_bytes_fp(&gate.coeffs);
    Ok(JsGateFp {
        typ: gate_type_to_i32(gate.typ),
        wires: core_wires_to_js(&gate.wires)?,
        coeffs: Uint8Array::from(coeff_bytes),
    })
}

fn core_gate_fq_to_js(gate: Gate<Fq>) -> napi::Result<JsGateFq> {
    let coeff_bytes = coeffs_to_bytes_fq(&gate.coeffs);
    Ok(JsGateFq {
        typ: gate_type_to_i32(gate.typ),
        wires: core_wires_to_js(&gate.wires)?,
        coeffs: Uint8Array::from(coeff_bytes),
    })
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_create() -> napi::Result<External<GateVectorHandleFp>> {
    Ok(External::new(GateVectorHandleFp::new()))
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_add(
    mut gates: External<GateVectorHandleFp>,
    gate: JsGateFp,
) -> napi::Result<()> {
    let gate = js_gate_fp_to_core(gate)?;
    gates.as_mut().inner_mut().push_gate(gate.into());
    Ok(())
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_get(
    gates: External<GateVectorHandleFp>,
    i: i32,
) -> napi::Result<JsGateFp> {
    let gate = gates
        .as_ref()
        .inner()
        .get_gate(i as usize)
        .map(core_gate_fp_to_js)
        .unwrap_or_else(|| {
            Err(Error::new(
                Status::InvalidArg,
                format!("gate index {i} out of bounds"),
            ))
        })?;
    Ok(gate)
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_len(
    gates: External<GateVectorHandleFp>,
) -> napi::Result<u32> {
    let len = gates.as_ref().inner().len();
    Ok(u32::try_from(len).map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "gate vector length exceeds u32".to_string(),
        )
    })?)
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_wrap(
    mut gates: External<GateVectorHandleFp>,
    t: JsWire,
    h: JsWire,
) -> napi::Result<()> {
    let target = js_wire_to_wire(&t)?;
    let replacement = js_wire_to_wire(&h)?;
    gates.as_mut().inner_mut().wrap_wire(target, replacement);
    Ok(())
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_digest(
    gates: External<GateVectorHandleFp>,
    public_input_size: u32,
) -> Uint8Array {
    Uint8Array::from(gates.as_ref().inner().digest(public_input_size as usize))
}

#[napi]
pub fn caml_pasta_fp_plonk_circuit_serialize(
    gates: External<GateVectorHandleFp>,
    public_input_size: u32,
) -> napi::Result<String> {
    gates
        .as_ref()
        .inner()
        .serialize(public_input_size as usize)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_create() -> napi::Result<External<GateVectorHandleFq>> {
    Ok(External::new(GateVectorHandleFq::new()))
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_add(
    mut gates: External<GateVectorHandleFq>,
    gate: JsGateFq,
) -> napi::Result<()> {
    let gate = js_gate_fq_to_core(gate)?;
    gates.as_mut().inner_mut().push_gate(gate.into());
    Ok(())
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_get(
    gates: External<GateVectorHandleFq>,
    i: i32,
) -> napi::Result<JsGateFq> {
    let gate = gates
        .as_ref()
        .inner()
        .get_gate(i as usize)
        .map(core_gate_fq_to_js)
        .unwrap_or_else(|| {
            Err(Error::new(
                Status::InvalidArg,
                format!("gate index {i} out of bounds"),
            ))
        })?;
    Ok(gate)
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_len(
    gates: External<GateVectorHandleFq>,
) -> napi::Result<u32> {
    let len = gates.as_ref().inner().len();
    Ok(u32::try_from(len).map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "gate vector length exceeds u32".to_string(),
        )
    })?)
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_wrap(
    mut gates: External<GateVectorHandleFq>,
    t: JsWire,
    h: JsWire,
) -> napi::Result<()> {
    let target = js_wire_to_wire(&t)?;
    let replacement = js_wire_to_wire(&h)?;
    gates.as_mut().inner_mut().wrap_wire(target, replacement);
    Ok(())
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_digest(
    gates: External<GateVectorHandleFq>,
    public_input_size: u32,
) -> Uint8Array {
    Uint8Array::from(gates.as_ref().inner().digest(public_input_size as usize))
}

#[napi]
pub fn caml_pasta_fq_plonk_circuit_serialize(
    gates: External<GateVectorHandleFq>,
    public_input_size: u32,
) -> napi::Result<String> {
    gates
        .as_ref()
        .inner()
        .serialize(public_input_size as usize)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_to_bytes(
    gates: External<GateVectorHandleFp>,
) -> napi::Result<Uint8Array> {
    let bytes = rmp_serde::to_vec(gates.as_ref().inner().as_slice())
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Uint8Array::from(bytes))
}

#[napi]
pub fn caml_pasta_fp_plonk_gate_vector_from_bytes(
    bytes: Uint8Array,
) -> napi::Result<External<GateVectorHandleFp>> {
    let gates: Vec<CircuitGate<Fp>> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(GateVectorHandleFp(GateVector::from_vec(
        gates,
    ))))
}

#[napi]
pub fn caml_pasta_fq_plonk_gate_vector_from_bytes(
    bytes: Uint8Array,
) -> napi::Result<External<GateVectorHandleFq>> {
    let gates: Vec<CircuitGate<Fq>> = rmp_serde::from_slice(bytes.as_ref())
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(External::new(GateVectorHandleFq(GateVector::from_vec(
        gates,
    ))))
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
                [<Napi $field_name:camel GateVector>](Vec::new())
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_add>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                gate: [<Napi $field_name:camel Gate>],
            ) -> Result<()> {
                vector.0.push(gate.into_inner()?);
                Ok(())
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_get>](
                vector: &[<Napi $field_name:camel GateVector>],
                index: i32,
            ) -> [<Napi $field_name:camel Gate>] {
                [<Napi $field_name:camel Gate>]::from_inner(&vector.0[index as usize])
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_len>](
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> i32 {
                vector.0.len() as i32
            }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_wrap>](
                vector: &mut [<Napi $field_name:camel GateVector>],
                target: NapiWire,
                head: NapiWire,
            ) {
                vector.0[target.row as usize].wires[target.col as usize] = KimchiWire::from(head);
              }

            #[napi]
            pub fn [<caml_pasta_ $field_name:snake _plonk_gate_vector_digest>](
                public_input_size: i32,
                vector: &[<Napi $field_name:camel GateVector>],
            ) -> Uint8Array {
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
