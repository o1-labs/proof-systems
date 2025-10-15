use std::convert::TryFrom;

use arkworks::{WasmPastaFp, WasmPastaFq};
use kimchi::circuits::{
    gate::GateType,
    wires::Wire,
};
use mina_curves::pasta::{Fp, Fq};
use napi::bindgen_prelude::{Error, External, Status, Uint8Array};
use napi_derive::napi;
use plonk_wasm::gate_vector::{
    CoreGate as Gate,
    CoreGateVector as GateVector,
    CoreGateWires as GateWires,
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
pub fn caml_pasta_fp_plonk_gate_vector_create(
) -> napi::Result<External<GateVectorHandleFp>> {
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
    Uint8Array::from(
        gates
            .as_ref()
            .inner()
            .digest(public_input_size as usize),
    )
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
pub fn caml_pasta_fq_plonk_gate_vector_create(
) -> napi::Result<External<GateVectorHandleFq>> {
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
    Uint8Array::from(
        gates
            .as_ref()
            .inner()
            .digest(public_input_size as usize),
    )
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
