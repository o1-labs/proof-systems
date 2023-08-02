use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    proof::ProverProof,
    prover_index::{testing::new_index_for_test, ProverIndex},
    verifier::{batch_verify, Context},
    verifier_index::VerifierIndex,
};
use ark_ec::AffineCurve;
use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use poly_commitment::commitment::CommitmentCurve;
use std::{array, rc::Rc};
use turbo::poly_ops::GpuContext;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

pub struct BenchmarkCtx {
    num_gates: usize,
    group_map: BWParameters<VestaParameters>,
    index: ProverIndex<Vesta>,
    verifier_index: VerifierIndex<Vesta>,
    gpu: Rc<GpuContext>,
}

#[derive(Clone)]
pub struct GatesToCompile(Vec<CircuitGate<<Vesta as AffineCurve>::ScalarField>>);
#[derive(Clone)]
pub struct Group(<Vesta as CommitmentCurve>::Map);
impl BenchmarkCtx {
    pub fn srs_size(&self) -> usize {
        math::ceil_log2(self.index.srs.max_degree())
    }

    pub fn create_gates(srs_size_log2: u32) -> GatesToCompile {
        let num_gates = ((1 << srs_size_log2) - 10) as usize;

        // create the circuit
        let mut gates = vec![];

        #[allow(clippy::explicit_counter_loop)]
        for row in 0..num_gates {
            let wires = Wire::for_row(row);
            gates.push(CircuitGate::create_generic_gadget(
                wires,
                GenericGateSpec::Const(1u32.into()),
                None,
            ));
        }
        GatesToCompile(gates)
    }
    pub fn compile_gates(
        srs_size_log2: u32,
        gates: GatesToCompile,
        group_map: Group,
        gpu: Option<Rc<GpuContext>>,
    ) -> BenchmarkCtx {
        let gates = gates.0;
        let num_gates = gates.len();

        // create the index
        let index = new_index_for_test(gates, 0);

        assert_eq!(index.cs.domain.d1.log_size_of_group, srs_size_log2, "the test wanted to use an SRS of size {srs_size_log2} but the domain size ended up being {}", index.cs.domain.d1.log_size_of_group);

        // create the verifier index
        let verifier_index = index.verifier_index();
        let group_map = group_map.0;

        let gpu = gpu.unwrap_or_else(|| Rc::new(GpuContext::new()));
        BenchmarkCtx {
            num_gates,
            group_map,
            index,
            verifier_index,
            gpu,
        }
    }
    pub fn group() -> Group {
        Group(<Vesta as CommitmentCurve>::Map::setup())
    }
    /// This will create a context that allows for benchmarks of `num_gates` gates (multiplication gates).
    pub fn new(srs_size_log2: u32, gpu: Option<Rc<GpuContext>>) -> Self {
        // there's some overhead that we need to remove (e.g. zk rows)
        let gates = Self::create_gates(srs_size_log2);

        // group map
        let group_map = Self::group();

        Self::compile_gates(srs_size_log2, gates, group_map, gpu)
    }

    /// Produces a proof
    pub fn create_proof(&self) -> (ProverProof<Vesta>, Vec<Fp>) {
        // create witness
        let witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![1u32.into(); self.num_gates]);

        let public_input = witness[0][0..self.index.cs.public].to_vec();

        // add the proof to the batch
        (
            ProverProof::create::<BaseSponge, ScalarSponge>(
                &self.group_map,
                witness,
                &[],
                &self.index,
                Some(self.gpu.clone()),
            )
            .unwrap(),
            public_input,
        )
    }

    pub fn batch_verification(&self, batch: &[(ProverProof<Vesta>, Vec<Fp>)]) {
        // verify the proof
        let batch: Vec<_> = batch
            .iter()
            .map(|(proof, public)| Context {
                verifier_index: &self.verifier_index,
                proof,
                public_input: public,
            })
            .collect();
        batch_verify::<Vesta, BaseSponge, ScalarSponge>(&self.group_map, &batch).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_bench() {
        // context created in 21.2235 ms
        let start = Instant::now();
        let srs_size = 4;
        let ctx = BenchmarkCtx::new(srs_size, None);
        println!("testing bench code for SRS of size {srs_size}");
        println!("context created in {}s", start.elapsed().as_secs());

        // proof created in 7.1227 ms
        let start = Instant::now();
        let (proof, public_input) = ctx.create_proof();
        println!("proof created in {}s", start.elapsed().as_secs());

        // proof verified in 1.710 ms
        let start = Instant::now();
        ctx.batch_verification(&vec![(proof, public_input)]);
        println!("proof verified in {}", start.elapsed().as_secs());
    }
}
