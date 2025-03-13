use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

pub struct MinRoot<F: PrimeField> {
    pub x: F,
    pub y: F,
    pub n: u64,
}

impl<F: PrimeField, E: InterpreterEnv> ZkApp<E> for MinRoot<F> {
    fn dummy_witness<F: PrimeField>(&self, srs_size: usize) -> Vec<Vec<F>> {}

    fn run(&self, env: &mut E) {
        let x1 = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
        let y1 = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
        let n = {
            let pos = env.allocate();
            env.fetch_input(pos)
        };
    }

    fn setup(&mut self, _env: &mut E) {}
}
