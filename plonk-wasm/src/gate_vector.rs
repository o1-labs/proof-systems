//! A GateVector: this is used to represent a list of gates.

use kimchi::circuits::{
    gate::{Circuit, CircuitGate, GateType},
    wires::Wire,
};
use o1_utils::hasher::CryptoDigest;
use paste::paste;
use wasm_bindgen::prelude::*;
use wasm_types::FlatVector as WasmFlatVector;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub struct WasmGateWires(
    pub Wire,
    pub Wire,
    pub Wire,
    pub Wire,
    pub Wire,
    pub Wire,
    pub Wire,
);

#[wasm_bindgen]
impl WasmGateWires {
    #[wasm_bindgen(constructor)]
    pub fn new(w0: Wire, w1: Wire, w2: Wire, w3: Wire, w4: Wire, w5: Wire, w6: Wire) -> Self {
        WasmGateWires(w0, w1, w2, w3, w4, w5, w6)
    }
}

macro_rules! impl_gate_vector {
    ($name: ident,
     $WasmF: ty,
     $F: ty,
     $field_name: ident) => {
        paste! {
            #[wasm_bindgen]
            pub struct [<Wasm $field_name:camel GateVector>] {
                #[wasm_bindgen(skip)] 
                pub data: Vec<CircuitGate<$F>>,
                #[wasm_bindgen(skip)]
                pub id: u64,
            }
            pub type WasmGateVector = [<Wasm $field_name:camel GateVector>];
            
            impl Drop for [<Wasm $field_name:camel GateVector>] {
                fn drop(&mut self) {
                    let size = self.data.capacity() * std::mem::size_of::<CircuitGate<$F>>();
                    crate::memory_tracker::log_deallocation(concat!("Wasm", stringify!($field_name), "GateVector"), size, self.id);
                }
            }

            #[wasm_bindgen]
            pub struct [<Wasm $field_name:camel Gate>] {
                pub typ: GateType, // type of the gate
                pub wires: WasmGateWires,  // gate wires
                #[wasm_bindgen(skip)] pub coeffs: Vec<$WasmF>,  // constraints vector
                #[wasm_bindgen(skip)] pub id: u64,
            }
            
            impl Drop for [<Wasm $field_name:camel Gate>] {
                fn drop(&mut self) {
                    let size = std::mem::size_of::<Self>() + self.coeffs.capacity() * std::mem::size_of::<$WasmF>();
                    crate::memory_tracker::log_deallocation(concat!("Wasm", stringify!($field_name), "Gate"), size, self.id);
                }
            }

            #[wasm_bindgen]
            impl [<Wasm $field_name:camel Gate>] {
                #[wasm_bindgen(constructor)]
                pub fn new(
                    typ: GateType,
                    wires: WasmGateWires,
                    coeffs: WasmFlatVector<$WasmF>) -> Self {
                    let id = crate::memory_tracker::next_id();
                    let coeffs_vec: Vec<$WasmF> = coeffs.into();
                    let size = std::mem::size_of::<Self>() + coeffs_vec.capacity() * std::mem::size_of::<$WasmF>();
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "Gate"), size, file!(), line!(), id);
                    Self {
                        typ,
                        wires,
                        coeffs: coeffs_vec,
                        id,
                    }
                }
            }

            impl From<CircuitGate<$F>> for [<Wasm $field_name:camel Gate>]
            {
                fn from(cg: CircuitGate<$F>) -> Self {
                    let id = crate::memory_tracker::next_id();
                    let coeffs: Vec<$WasmF> = cg.coeffs.into_iter().map(Into::into).collect();
                    let size = std::mem::size_of::<Self>() + coeffs.capacity() * std::mem::size_of::<$WasmF>();
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "Gate"), size, file!(), line!(), id);
                    Self {
                        typ: cg.typ,
                        wires: WasmGateWires(
                            cg.wires[0],
                            cg.wires[1],
                            cg.wires[2],
                            cg.wires[3],
                            cg.wires[4],
                            cg.wires[5],
                            cg.wires[6]),
                        coeffs,
                        id,
                    }
                }
            }

            impl From<&CircuitGate<$F>> for [<Wasm $field_name:camel Gate>]
            {
                fn from(cg: &CircuitGate<$F>) -> Self {
                    let id = crate::memory_tracker::next_id();
                    let coeffs: Vec<$WasmF> = cg.coeffs.clone().into_iter().map(Into::into).collect();
                    let size = std::mem::size_of::<Self>() + coeffs.capacity() * std::mem::size_of::<$WasmF>();
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "Gate"), size, file!(), line!(), id);
                    Self {
                        typ: cg.typ,
                        wires: WasmGateWires(
                            cg.wires[0],
                            cg.wires[1],
                            cg.wires[2],
                            cg.wires[3],
                            cg.wires[4],
                            cg.wires[5],
                            cg.wires[6]),
                        coeffs,
                        id,
                    }
                }
            }

            impl From<[<Wasm $field_name:camel Gate>]> for CircuitGate<$F>
            {
                fn from(ccg: [<Wasm $field_name:camel Gate>]) -> Self {
                    Self {
                        typ: ccg.typ,
                        wires: [
                            ccg.wires.0,
                            ccg.wires.1,
                            ccg.wires.2,
                            ccg.wires.3,
                            ccg.wires.4,
                            ccg.wires.5,
                            ccg.wires.6
                        ],
                        coeffs: ccg.coeffs.clone().into_iter().map(Into::into).collect(),
                    }
                }
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_create>]() -> WasmGateVector {
                let id = crate::memory_tracker::next_id();
                let data = Vec::new();
                let size = data.capacity() * std::mem::size_of::<CircuitGate<$F>>();
                crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "GateVector"), size, file!(), line!(), id);
                [<Wasm $field_name:camel GateVector>] { data, id }
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_add>](
                v: &mut WasmGateVector,
                gate: [<Wasm $field_name:camel Gate>],
            ) {
                let gate: CircuitGate<$F> = gate.into();
                v.data.push(gate);
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_get>](
                v: &WasmGateVector,
                i: i32,
            ) -> [<Wasm $field_name:camel Gate>] {
                (&(v.data)[i as usize]).into()
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_len>](
                v: &WasmGateVector,
            ) -> usize {
                v.data.len()
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_wrap>](
                v: &mut WasmGateVector,
                t: Wire,
                h: Wire,
            ) {
                (v.data)[t.row as usize].wires[t.col as usize] = h.into();
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_digest>](
                public_input_size: usize,
                v: &WasmGateVector
            ) -> Box<[u8]> {
                Circuit::new(public_input_size, &(v.data)).digest().to_vec().into_boxed_slice()
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_circuit_serialize>](
                public_input_size: usize,
                v: &WasmGateVector
            ) -> String {
                let circuit = Circuit::new(public_input_size, &v.data);
                serde_json::to_string(&circuit).expect("couldn't serialize constraints")
            }
        }
    };
}

pub mod fp {
    use super::*;
    use arkworks::WasmPastaFp as WasmF;
    use mina_curves::pasta::Fp as F;

    impl_gate_vector!(fp, WasmF, F, Fp);
}

//
// Fq
//

pub mod fq {
    use super::*;
    use arkworks::WasmPastaFq as WasmF;
    use mina_curves::pasta::Fq as F;

    impl_gate_vector!(fq, WasmF, F, Fq);
}
