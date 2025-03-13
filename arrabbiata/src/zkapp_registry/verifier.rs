//! This module contains a generic verifier for Arrabbiata.
//!
//! The verifier is implemented as a ZkApp, and is responsible to build the
//! verification of a previous execution trace.
//!
//! Considering the verifier as a ZkApp allows to reuse the same interface.
//! Also, it eases the development of other verifiers, as the interface is
//! generic and can be reused.

use crate::{
    column::Gadget,
    curve::ArrabbiataCurve,
    interpreter::{self, InterpreterEnv, VERIFIER_STARTING_INSTRUCTION},
    zkapp_registry::ZkApp,
};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

pub struct Verifier<C: ArrabbiataCurve>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    pub _field: std::marker::PhantomData<C>,
}

impl<C: ArrabbiataCurve> ZkApp<C> for Verifier<C>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    fn dummy_witness(&self, _srs_size: usize) -> Vec<Vec<C::ScalarField>> {
        unimplemented!("Dummy witness for the verifier is not implemented yet")
    }

    fn run<E: InterpreterEnv>(&self, _env: &mut E) {}

    fn setup(&self, app_size: usize) -> Vec<Gadget> {
        let mut circuit: Vec<Gadget> = vec![];
        let mut curr_instruction = VERIFIER_STARTING_INSTRUCTION;
        for _i in 0..app_size - 1 {
            circuit.push(Gadget::from(curr_instruction));
            curr_instruction = interpreter::fetch_next_instruction(curr_instruction);
        }
        // Additional row for the Poseidon hash
        circuit.push(Gadget::NoOp);
        assert_eq!(circuit.len(), app_size);
        circuit
    }
}
