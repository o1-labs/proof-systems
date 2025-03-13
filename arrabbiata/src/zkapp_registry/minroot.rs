use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

use super::ZkApp;
use crate::{
    column::Gadget,
    curve::ArrabbiataCurve,
    interpreter::{Instruction, InterpreterEnv},
};

pub struct MinRoot<F: PrimeField> {
    pub x: F,
    pub y: F,
    pub n: u64,
}

impl<C: ArrabbiataCurve> ZkApp<C> for MinRoot<C::ScalarField>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    fn dummy_witness(&self, _srs_size: usize) -> Vec<Vec<C::ScalarField>> {
        unimplemented!()
    }

    fn fetch_next_instruction(&self, _current_instr: Instruction) -> Instruction {
        unimplemented!()
    }

    fn run<E: InterpreterEnv>(&self, env: &mut E) {
        let _x1 = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
        let _y1 = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
        let _n = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
    }

    fn setup(&self, _app_size: usize) -> Vec<Gadget> {
        unimplemented!()
    }
}
