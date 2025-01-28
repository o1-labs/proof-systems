use std::array;

use ark_serialize::CanonicalDeserialize;
use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use poly_commitment::{
    commitment::{CommitmentCurve, PolyComm},
    ipa::OpeningProof,
    SRS,
};
use std::{fs::File, io::BufReader};

use crate::{
    circuits::{
        gate::CircuitGate,
        lookup::runtime_tables::RuntimeTable,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    proof::{ProverProof, RecursionChallenge},
    prover_index::{testing::new_index_for_test, ProverIndex},
    verifier::{batch_verify, Context},
};

type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

pub struct BenchmarkCtx {
    pub num_gates: usize,
    group_map: BWParameters<VestaParameters>,
    index: ProverIndex<Vesta, OpeningProof<Vesta>>,
}

impl BenchmarkCtx {
    pub fn srs_size(&self) -> usize {
        math::ceil_log2(self.index.srs.max_poly_size())
    }

    /// This will create a context that allows for benchmarks of `num_gates`
    /// gates (multiplication gates).
    pub fn new(srs_size_log2: u32) -> Self {
        // there's some overhead that we need to remove (e.g. zk rows)

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

        // group map
        let group_map = <Vesta as CommitmentCurve>::Map::setup();

        // create the index
        let mut index = new_index_for_test(gates, 0);

        assert_eq!(index.cs.domain.d1.log_size_of_group, srs_size_log2, "the test wanted to use an SRS of size {srs_size_log2} but the domain size ended up being {}", index.cs.domain.d1.log_size_of_group);

        // create the verifier index
        index.compute_verifier_index_digest::<BaseSponge>();

        // just in case check that lagrange bases are generated
        index.srs.get_lagrange_basis(index.cs.domain.d1);

        BenchmarkCtx {
            num_gates,
            group_map,
            index,
        }
    }

    /// Produces a proof
    pub fn create_proof(&self) -> (ProverProof<Vesta, OpeningProof<Vesta>>, Vec<Fp>) {
        // create witness
        let witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![1u32.into(); self.num_gates]);

        let public_input = witness[0][0..self.index.cs.public].to_vec();

        // add the proof to the batch
        (
            ProverProof::create::<BaseSponge, ScalarSponge, _>(
                &self.group_map,
                witness,
                &[],
                &self.index,
                &mut rand::rngs::OsRng,
            )
            .unwrap(),
            public_input,
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn batch_verification(&self, batch: &[(ProverProof<Vesta, OpeningProof<Vesta>>, Vec<Fp>)]) {
        // verify the proof
        let batch: Vec<_> = batch
            .iter()
            .map(|(proof, public)| Context {
                verifier_index: self.index.verifier_index.as_ref().unwrap(),
                proof,
                public_input: public,
            })
            .collect();
        batch_verify::<Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta>>(
            &self.group_map,
            &batch,
        )
        .unwrap();
    }
}

pub fn bench_arguments_from_file(
    srs: poly_commitment::ipa::SRS<Vesta>,
    seed: String,
) -> (
    ProverIndex<Vesta, OpeningProof<Vesta>>,
    [Vec<Fp>; COLUMNS],
    Vec<RuntimeTable<Fp>>,
    Vec<RecursionChallenge<Vesta>>,
) {
    let bytes1: Vec<u8> = std::fs::read(format!("../test_kimchi_input_{}.ser", seed)).unwrap();
    let (witness, runtime_tables_as_vec, prev_as_pairs): (
        [Vec<_>; COLUMNS],
        Vec<(u32, Vec<Fp>)>,
        Vec<_>,
    ) = CanonicalDeserialize::deserialize_uncompressed(bytes1.as_slice()).unwrap();

    let runtime_tables: Vec<RuntimeTable<_>> = runtime_tables_as_vec
        .into_iter()
        .map(|(id_u32, data)| RuntimeTable {
            id: id_u32 as i32,
            data,
        })
        .collect();

    let prev: Vec<RecursionChallenge<_>> = prev_as_pairs
        .into_iter()
        .map(|(chals, chunks)| RecursionChallenge {
            chals,
            comm: PolyComm { chunks },
        })
        .collect();

    // serialized index does not have many fields including SRS
    let mut reader2 =
        BufReader::new(File::open(format!("../test_kimchi_index_{}.ser", seed)).unwrap());
    let index_orig: ProverIndex<Vesta, OpeningProof<Vesta>> =
        rmp_serde::from_read(&mut reader2).unwrap();

    let cs = index_orig.cs.clone();
    let endo = cs.endo;
    let mut index: ProverIndex<Vesta, OpeningProof<Vesta>> =
        ProverIndex::create(cs, endo, srs.into());
    index.compute_verifier_index_digest::<BaseSponge>();

    (index, witness, runtime_tables, prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bench_mina_kimchi_prover() {
        use crate::{
            bench::{BaseSponge, ScalarSponge},
            proof::ProverProof,
        };
        use groupmap::GroupMap;

        //let seed = "18402993648648599487";
        let seed = "10200493143626649653";

        let srs = crate::precomputed_srs::get_srs_test();
        let (index, witness, runtime_tables, prev) =
            bench_arguments_from_file(srs, seed.to_string());

        std::thread::sleep(std::time::Duration::from_secs(1));

        let group_map = GroupMap::<_>::setup();
        for _i in 0..3 {
            let _proof = ProverProof::create_recursive::<BaseSponge, ScalarSponge, _>(
                &group_map,
                witness.clone(),
                &runtime_tables,
                &index,
                prev.clone(),
                None,
                &mut rand::rngs::OsRng,
            );
        }
    }
}
