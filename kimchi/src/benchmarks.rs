use crate::{
    bench::{self, BenchmarkCtx},
    proof::ProverProof,
};
use benchmarking::{Benchmark, BlackBox};
use mina_curves::pasta::{Fp, Vesta};

pub struct Proving;

impl Benchmark for Proving {
    type Data = ();

    type RefinedData = BenchmarkCtx;

    fn prepare_data() -> Self::Data {}

    fn refine_data(parameter: usize, _data: &Self::Data) -> Self::RefinedData {
        BenchmarkCtx::new(parameter as u32)
    }

    fn default_parameters() -> Option<Vec<usize>> {
        Some(vec![8, 9, 10, 12, 14, 16])
    }

    fn function<B: BlackBox>(_parameter: usize, data: &Self::RefinedData) {
        B::black_box(data.create_proof());
    }
}

pub struct Verifying;
impl Benchmark for Verifying {
    type Data = ();

    type RefinedData = (BenchmarkCtx, Vec<(ProverProof<Vesta>, Vec<Fp>)>);

    fn prepare_data() -> Self::Data {}

    fn refine_data(parameter: usize, _data: &Self::Data) -> Self::RefinedData {
        let ctx = BenchmarkCtx::new(parameter as u32);
        let proof = ctx.create_proof();
        (ctx, vec![proof])
    }

    fn default_parameters() -> Option<Vec<usize>> {
        Some(vec![8, 9, 10, 12, 14, 16])
    }

    fn function<B: BlackBox>(_parameter: usize, data: &Self::RefinedData) {
        let (ctx, proof) = data;
        ctx.batch_verification(proof);
    }
}

pub struct Compiling;
impl Benchmark for Compiling {
    type Data = ();

    type RefinedData = (bench::GatesToCompile, bench::Group);

    fn prepare_data() -> Self::Data {}

    fn refine_data(parameter: usize, _data: &Self::Data) -> Self::RefinedData {
        let gates = BenchmarkCtx::create_gates(parameter as u32);
        let group_map = BenchmarkCtx::group();
        (gates, group_map)
    }

    fn default_parameters() -> Option<Vec<usize>> {
        Some(vec![8, 9, 10, 12, 14, 16])
    }

    fn function<B: BlackBox>(parameter: usize, data: &Self::RefinedData) {
        let (gates, group_map) = data.clone();
        B::black_box(BenchmarkCtx::compile_gates(
            parameter as u32,
            gates,
            group_map,
        ));
    }
}
