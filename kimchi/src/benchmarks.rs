use crate::{
    bench::{self, BaseSponge, BenchmarkCtx, ScalarSponge},
    circuits::{
        gate::{CircuitGate, Connect},
        polynomial::COLUMNS,
        polynomials::{
            generic::GenericGateSpec,
            poseidon::{generate_witness, POS_ROWS_PER_HASH},
        },
        wires::Wire,
    },
    curve::KimchiCurve,
    proof::ProverProof,
    prover_index::{testing::new_index_for_test, ProverIndex},
};
use benchmarking::{Benchmark, BlackBox};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta};
use num_traits::Zero;
use poly_commitment::commitment::CommitmentCurve;

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

pub struct HashChain;

impl Benchmark for HashChain {
    type Data = ();

    type RefinedData = (ProverIndex<Vesta>, usize, usize);

    fn prepare_data() -> Self::Data {
        ()
    }

    fn refine_data(parameter: usize, _data: &Self::Data) -> (ProverIndex<Vesta>, usize, usize) {
        // const CHAIN_LEN: usize = 1 << 8;
        let chain_length = 1 << parameter;

        let gates = (POS_ROWS_PER_HASH + 1) * chain_length + 2;
        let mut gates = Vec::with_capacity(gates);

        //for final hash
        gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Pub,
            None,
        ));
        //for preimage
        //TODO: for security, second and third should be fixed to zero or something
        gates.push(CircuitGate::create_generic_gadget(
            Wire::for_row(1),
            GenericGateSpec::Pub,
            None,
        ));

        let round_constants = &*Vesta::sponge_params().round_constants;
        for _ in 0..chain_length {
            let row = gates.len();
            let copy = [0, 1, 2].map(|i| ((row, i), (row - 1, i)));
            let preimage = Wire::for_row(row);
            let image = Wire::for_row(row + POS_ROWS_PER_HASH);

            let (poseidon, _) =
                CircuitGate::<Fp>::create_poseidon_gadget(row, [preimage, image], round_constants);
            gates.extend(poseidon);
            for (l, r) in copy {
                gates.connect_cell_pair(l, r);
            }
        }
        let last = gates.len() - 1;
        gates.connect_cell_pair((0, 0), (last, 0));
        gates.connect_cell_pair((0, 1), (last, 1));

        let gates_len = gates.len();
        let index = new_index_for_test::<Vesta>(gates, 2);
        (index, chain_length, gates_len)
    }

    fn default_parameters() -> Option<Vec<usize>> {
        Some(vec![4, 5, 6, 7, 8, 9, 10, 11, 12])
    }

    fn function<B: BlackBox>(_parameter: usize, data: &Self::RefinedData) {
        let (index, chain_length, gates_len) = data;
        let col = vec![Fp::zero(); *gates_len];
        let mut witness = [(); COLUMNS].map(|_| col.clone());

        let input = [Fp::from(123u32), Fp::from(0u32), Fp::from(0u32)];
        witness[0][1] = input[0];
        witness[1][1] = input[1];
        witness[2][1] = input[2];
        let param = Vesta::sponge_params();
        for i in 0..*chain_length {
            let w = &witness;
            let input = { [&w[0], &w[1], &w[2]].map(|c| c[(POS_ROWS_PER_HASH + 1) * i + 1]) };
            let row = i * (POS_ROWS_PER_HASH + 1) + 2;
            generate_witness(row, param, &mut witness, input);
        }
        let last = witness[0].len() - 1;
        witness[0][0] = witness[0][last];
        witness[1][0] = witness[1][last];
        witness[2][0] = witness[2][last];

        let group_map = <<Vesta as CommitmentCurve>::Map as GroupMap<_>>::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index)
                .unwrap();
        B::black_box(proof);
    }
}
