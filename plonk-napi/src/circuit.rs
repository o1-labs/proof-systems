use crate::{build_info::report_native_call, pasta_fp_plonk_index::WasmPastaFpPlonkIndex};
use ark_ff::PrimeField;
use kimchi::circuits::{constraints::ConstraintSystem, gate::CircuitGate};
use mina_curves::pasta::Fp;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Serialize;

#[derive(Serialize)]
struct Circuit<F>
where
    F: PrimeField,
{
    public_input_size: usize,
    #[serde(bound = "CircuitGate<F>: Serialize")]
    gates: Vec<CircuitGate<F>>,
}

impl<F> From<&ConstraintSystem<F>> for Circuit<F>
where
    F: PrimeField,
{
    fn from(cs: &ConstraintSystem<F>) -> Self {
        Self {
            public_input_size: cs.public,
            gates: cs.gates.to_vec(),
        }
    }
}

#[napi(js_name = "prover_to_json")]
pub fn prover_to_json(prover_index: &External<WasmPastaFpPlonkIndex>) -> String {
    report_native_call();

    let circuit: Circuit<Fp> = prover_index.0.cs.as_ref().into();
    serde_json::to_string(&circuit).expect("couldn't serialize constraints")
}
