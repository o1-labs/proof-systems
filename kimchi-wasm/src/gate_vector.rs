//! A GateVector: this is used to represent a list of gates.

use ark_ff::PrimeField;
use kimchi::circuits::{
    gate::{Circuit, CircuitGate, GateType},
    wires::Wire,
};
use o1_utils::hasher::CryptoDigest;
use paste::paste;
use wasm_bindgen::prelude::*;
use wasm_types::FlatVector as WasmFlatVector;

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

        pub fn serialize(&self, public_input_size: usize) -> Result<String, serde_json::Error> {
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

pub use self::shared::{
    Gate as CoreGate, GateVector as CoreGateVector, GateWires as CoreGateWires,
};

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

impl From<CoreGateWires> for WasmGateWires {
    fn from(wires: CoreGateWires) -> Self {
        let array = wires.into_array();
        WasmGateWires(
            array[0], array[1], array[2], array[3], array[4], array[5], array[6],
        )
    }
}

impl From<WasmGateWires> for CoreGateWires {
    fn from(wires: WasmGateWires) -> Self {
        CoreGateWires::new([
            wires.0, wires.1, wires.2, wires.3, wires.4, wires.5, wires.6,
        ])
    }
}

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
            pub struct [<Wasm $field_name:camel GateVector>](
                #[wasm_bindgen(skip)] pub CoreGateVector<$F>);
            pub type WasmGateVector = [<Wasm $field_name:camel GateVector>];

            #[wasm_bindgen]
            impl [<Wasm $field_name:camel GateVector>] {
                #[wasm_bindgen(js_name = "serialize")]
                pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                    rmp_serde::to_vec(self.0.as_slice())
                        .map_err(|e| JsError::new(&format!("gate vector serialize failed: {e}")))
                }

                #[wasm_bindgen(js_name = "deserialize")]
                pub fn deserialize(bytes: &[u8]) -> Result<WasmGateVector, JsError> {
                    let gates: Vec<CircuitGate<$F>> = rmp_serde::from_slice(bytes)
                        .map_err(|e| JsError::new(&format!("gate vector deserialize failed: {e}")))?;
                    Ok([<Wasm $field_name:camel GateVector>](CoreGateVector::from_vec(gates)))
                }
            }

            #[wasm_bindgen]
            pub struct [<Wasm $field_name:camel Gate>] {
                pub typ: GateType,
                pub wires: WasmGateWires,
                #[wasm_bindgen(skip)] pub coeffs: Vec<$WasmF>,
            }

            #[wasm_bindgen]
            impl [<Wasm $field_name:camel Gate>] {
                #[wasm_bindgen(constructor)]
                pub fn new(
                    typ: GateType,
                    wires: WasmGateWires,
                    coeffs: WasmFlatVector<$WasmF>) -> Self {
                    Self {
                        typ,
                        wires,
                        coeffs: coeffs.into(),
                    }
                }
            }

            impl From<CoreGate<$F>> for [<Wasm $field_name:camel Gate>] {
                fn from(gate: CoreGate<$F>) -> Self {
                    Self {
                        typ: gate.typ,
                        wires: gate.wires.into(),
                        coeffs: gate.coeffs.into_iter().map(Into::into).collect(),
                    }
                }
            }

            impl From<&CoreGate<$F>> for [<Wasm $field_name:camel Gate>] {
                fn from(gate: &CoreGate<$F>) -> Self {
                    Self {
                        typ: gate.typ,
                        wires: gate.wires.into(),
                        coeffs: gate.coeffs.clone().into_iter().map(Into::into).collect(),
                    }
                }
            }

            impl From<CircuitGate<$F>> for [<Wasm $field_name:camel Gate>] {
                fn from(cg: CircuitGate<$F>) -> Self {
                    let gate: CoreGate<$F> = cg.into();
                    gate.into()
                }
            }

            impl From<&CircuitGate<$F>> for [<Wasm $field_name:camel Gate>] {
                fn from(cg: &CircuitGate<$F>) -> Self {
                    let gate: CoreGate<$F> = cg.into();
                    (&gate).into()
                }
            }

            impl From<[<Wasm $field_name:camel Gate>]> for CoreGate<$F> {
                fn from(ccg: [<Wasm $field_name:camel Gate>]) -> Self {
                    CoreGate {
                        typ: ccg.typ,
                        wires: ccg.wires.into(),
                        coeffs: ccg.coeffs.into_iter().map(Into::into).collect(),
                    }
                }
            }

            impl From<[<Wasm $field_name:camel Gate>]> for CircuitGate<$F> {
                fn from(ccg: [<Wasm $field_name:camel Gate>]) -> Self {
                    let gate: CoreGate<$F> = ccg.into();
                    gate.into()
                }
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_create>]() -> WasmGateVector {
                [<Wasm $field_name:camel GateVector>](CoreGateVector::new())
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_add>](
                v: &mut WasmGateVector,
                gate: [<Wasm $field_name:camel Gate>],
            ) {
                let gate: CoreGate<$F> = gate.into();
                v.0.push_gate(gate.into());
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_get>](
                v: &WasmGateVector,
                i: i32,
            ) -> [<Wasm $field_name:camel Gate>] {
                v.0
                    .get_gate(i as usize)
                    .map(|gate| gate.into())
                    .expect("index out of bounds")
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_len>](
                v: &WasmGateVector,
            ) -> usize {
                v.0.len()
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_wrap>](
                v: &mut WasmGateVector,
                t: Wire,
                h: Wire,
            ) {
                v.0.wrap_wire(t, h);
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_gate_vector_digest>](
                public_input_size: usize,
                v: &WasmGateVector
            ) -> Box<[u8]> {
                v.0.digest(public_input_size).into_boxed_slice()
            }

            #[wasm_bindgen]
            pub fn [<caml_pasta_ $name:snake _plonk_circuit_serialize>](
                public_input_size: usize,
                v: &WasmGateVector
            ) -> String {
                v.0
                    .serialize(public_input_size)
                    .expect("couldn't serialize constraints")
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

pub mod fq {
    use super::*;
    use arkworks::WasmPastaFq as WasmF;
    use mina_curves::pasta::Fq as F;

    impl_gate_vector!(fq, WasmF, F, Fq);
}
