use crate::{
    bench::{self, BaseSponge, BenchmarkCtx, ScalarSponge},
    circuits::{
        gate::CircuitGate,
        polynomial::COLUMNS,
        polynomials::{generic::GenericGateSpec, poseidon::generate_witness},
        wires::Wire,
    },
    curve::KimchiCurve,
    proof::ProverProof,
    prover_index::testing::new_index_for_test,
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

/*impl Benchmark for HashChain {
    type Data = ();

    type RefinedData;

    fn prepare_data() -> Self::Data {
        ()
    }

    fn refine_data(parameter: usize, data: &Self::Data) -> Self::RefinedData {
        todo!()
    }

    fn default_parameters() -> Option<Vec<usize>> {
        todo!()
    }

    fn function<B: BlackBox>(parameter: usize, data: &Self::RefinedData) {
        todo!()
    }
}
*/
//const ROWS_PER_HASH: usize = 11;
use crate::circuits::polynomials::poseidon::POS_ROWS_PER_HASH;

fn update_array<const N: usize, T>(array: [T; N], index: usize, new_element: T) -> [T; N] {
    let mut new = Some(new_element);
    let mut i = 0;
    let mut i = || {
        i += 1;
        i - 1
    };
    array.map(|e| match (i() == index, &mut new) {
        (true, new @ Some(_)) => new.take().unwrap_or(e),
        (true, None) | (false, _) => e,
    })
}
fn test() {
    const CHAIN_LEN: usize = 1 << 0;

    let gates = (POS_ROWS_PER_HASH + 1) * CHAIN_LEN + 2;
    let last = gates - 1;
    let mut gates = Vec::with_capacity(gates);

    //for final hash
    let wiring = update_array(Wire::for_row(0), 0, Wire { row: last, col: 0 });
    let wiring = update_array(wiring, 1, Wire { row: last, col: 1 });
    let wiring = update_array(wiring, 2, Wire { row: last, col: 2 });
    //to remove this wiring
    // let wiring = Wire::for_row(0);
    gates.push(CircuitGate::create_generic_gadget(
        wiring,
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
    println!("gates: {}", gates.len());

    let round_constants = &*Vesta::sponge_params().round_constants;
    //let mut preimage = first_row;
    for _ in 0..CHAIN_LEN {
        let row = gates.len();
        let last_row = row + POS_ROWS_PER_HASH;
        let preimage = {
            let pre = Wire::for_row(row);
            let row = row - 1;
            let pre = update_array(pre, 0, Wire { row, col: 0 });
            let pre = update_array(pre, 1, Wire { row, col: 1 });
            update_array(pre, 2, Wire { row, col: 2 })
        };
        //to remove this wiring
        // let preimage = Wire::for_row(row);
        let image = Wire::for_row(last_row);
        let (poseidon, _) =
            CircuitGate::<Fp>::create_poseidon_gadget(row, [preimage, image], round_constants);
        gates.extend(poseidon);
    }
    println!("gates: {}", gates.len());
    for (i, g) in gates.iter().enumerate() {
        println!("wiring{}: {:?}", i, &g.wires[0..4]);
    }

    //println!("gates: {:#?}", &gates[2]);

    let col = vec![Fp::zero(); gates.len()];
    let mut witness = [(); COLUMNS].map(|_| col.clone());
    println!("len: {}", witness[0].len());

    let input = [Fp::from(123u32), Fp::from(0u32), Fp::from(0u32)];
    witness[0][1] = input[0];
    witness[1][1] = input[1];
    witness[2][1] = input[2];
    let param = Vesta::sponge_params();
    for i in 0..CHAIN_LEN {
        let w = &witness;
        // let input = if i.is_zero()
        // input
        let input = { [&w[0], &w[1], &w[2]].map(|c| c[(POS_ROWS_PER_HASH + 1) * i + 1]) };
        let row = i * (POS_ROWS_PER_HASH + 1) + 2;
        generate_witness(row, param, &mut witness, input);
        let cr = row + POS_ROWS_PER_HASH;
        //do it at the start
        // witness[0][cr] = witness[0][cr - 1];
        // witness[1][cr] = witness[1][cr - 1];
        // witness[2][cr] = witness[2][cr - 1];
    }
    let last = witness[0].len() - 1;
    println!("last: {last}");
    witness[0][0] = witness[0][last];
    witness[1][0] = witness[1][last];
    witness[2][0] = witness[2][last];

    //BenchmarkCtx::compile_gates(srs_size_log2, gates, group_map)
    for r in [0, 1, 2, 12, 13] {
        println!("row: {}", r);
        for c in &witness[0..4] {
            print!("{} ", &c[r]);
        }
        println!();
    }

    let index = new_index_for_test::<Vesta>(gates, 2);

    let group_map = <<Vesta as CommitmentCurve>::Map as GroupMap<_>>::setup();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index).unwrap();
}

#[test]
fn pos_chain() {
    test();
}
