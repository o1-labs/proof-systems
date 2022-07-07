use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    proof::ProverProof,
    prover_index::{testing::new_index_for_test, ProverIndex},
    verifier::batch_verify,
    verifier_index::VerifierIndex,
};
use array_init::array_init;
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::vesta::VestaParameters;
use mina_curves::pasta::{fp::Fp, vesta::Affine};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

use o1_utils::math;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge<'a> = DefaultFqSponge<'a, VestaParameters, SpongeParams>;
type ScalarSponge<'a> = DefaultFrSponge<'a, Fp, SpongeParams>;

pub struct BenchmarkCtx {
    num_gates: usize,
    group_map: BWParameters<VestaParameters>,
    index: ProverIndex<Affine>,
    verifier_index: VerifierIndex<Affine>,
}

impl BenchmarkCtx {
    pub fn srs_size(&self) -> usize {
        math::ceil_log2(self.index.srs.max_degree())
    }

    /// This will create a context that allows for benchmarks of `num_gates` gates (multiplication gates).
    pub fn new(num_gates: usize) -> Self {
        // create the circuit
        let mut gates = vec![];

        #[allow(clippy::explicit_counter_loop)]
        for row in 0..num_gates {
            let wires = Wire::new(row);
            gates.push(CircuitGate::create_generic_gadget(
                wires,
                GenericGateSpec::Const(1u32.into()),
                None,
            ));
        }

        // group map
        let group_map = <Affine as CommitmentCurve>::Map::setup();

        // create the index
        let index = new_index_for_test(gates, 0);

        // create the verifier index
        let verifier_index = index.verifier_index();

        //
        BenchmarkCtx {
            num_gates,
            group_map,
            index,
            verifier_index,
        }
    }

    /// Produces a proof
    pub fn create_proof(&self) -> ProverProof<Affine> {
        // create witness
        let witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![1u32.into(); self.num_gates]);

        // add the proof to the batch
        ProverProof::create::<BaseSponge, ScalarSponge>(&self.group_map, witness, &[], &self.index)
            .unwrap()
    }

    pub fn batch_verification(&self, batch: Vec<ProverProof<Affine>>) {
        // verify the proof
        let batch: Vec<_> = batch
            .iter()
            .map(|proof| (&self.verifier_index, proof))
            .collect();
        batch_verify::<Affine, BaseSponge, ScalarSponge>(&self.group_map, &batch).unwrap();
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
        let ctx = BenchmarkCtx::new(1 << 4);
        println!("context created in {}", start.elapsed().as_secs());

        // proof created in 7.1227 ms
        let start = Instant::now();
        let proof = ctx.create_proof();
        println!("proof created in {}", start.elapsed().as_millis());

        // proof verified in 1.710 ms
        let start = Instant::now();
        ctx.batch_verification(vec![proof.clone()]);
        println!("proof verified in {}", start.elapsed().as_millis());
    }
}
