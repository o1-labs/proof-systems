#![allow(clippy::type_complexity)]

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::{Fp, Fq, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge, FqSponge},
};
use o1_utils::math;
use poly_commitment::{
    commitment::{CommitmentCurve, PolyComm},
    ipa::OpeningProof,
    SRS,
};
use rand::Rng;
use std::{array, fs::File, io::BufReader, path::PathBuf};

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        lookup::runtime_tables::RuntimeTable,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    curve::KimchiCurve,
    proof::{ProverProof, RecursionChallenge},
    prover_index::{testing::new_index_for_test, ProverIndex},
    verifier::{batch_verify, Context},
};

pub type BaseSpongeVesta = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
pub type ScalarSpongeVesta = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
pub type BaseSpongePallas = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi>;
pub type ScalarSpongePallas = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi>;

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
        index.compute_verifier_index_digest::<BaseSpongeVesta>();

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
            ProverProof::create::<BaseSpongeVesta, ScalarSpongeVesta, _>(
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
        batch_verify::<Vesta, BaseSpongeVesta, ScalarSpongeVesta, OpeningProof<Vesta>>(
            &self.group_map,
            &batch,
        )
        .unwrap();
    }
}

/// This function can be called before any call to a kimchi verfier,
/// in which case it will serialise kimchi inputs so that they can be
/// reused later for re-testing this particular prover. Used for
/// serialising real mina circuits from ocaml and bindings side.
pub fn bench_arguments_dump_into_file<G: KimchiCurve>(
    cs: &ConstraintSystem<G::ScalarField>,
    witness: &[Vec<G::ScalarField>; COLUMNS],
    runtime_tables: &[RuntimeTable<G::ScalarField>],
    prev: &[RecursionChallenge<G>],
) {
    let seed: u64 = rand::thread_rng().gen();

    let filename1 = format!("./kimchi_input_{}_{}.ser", G::NAME, seed);
    let filename2 = format!("./kimchi_cs_{}_{}.ser", G::NAME, seed);

    let mut file1 = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(PathBuf::from(filename1))
        .expect("failed to open file to write pasta_fp inputs");

    let runtime_tables_as_vec: Vec<(u32, Vec<G::ScalarField>)> = runtime_tables
        .iter()
        .map(|rt| {
            (
                rt.id.try_into().expect("rt must be non-negative"),
                rt.data.clone(),
            )
        })
        .collect();

    let prev_as_pairs: Vec<(_, _)> = prev
        .iter()
        .map(|rec_chal| {
            assert!(!rec_chal.comm.chunks.is_empty());
            (rec_chal.chals.clone(), rec_chal.comm.chunks.clone())
        })
        .collect();

    let mut bytes1: Vec<u8> = vec![];
    CanonicalSerialize::serialize_uncompressed(
        &(
            witness.clone(),
            runtime_tables_as_vec.clone(),
            prev_as_pairs.clone(),
        ),
        &mut bytes1,
    )
    .unwrap();

    file1.write_all(&bytes1).expect("failed to write file");
    file1.flush().expect("failed to flush file");

    let mut file2 = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(filename2)
        .expect("failed to open file to write pasta_fp inputs");

    let bytes2: Vec<u8> = rmp_serde::to_vec(&cs).unwrap();
    file2.write_all(&bytes2).expect("failed to write file");
    file2.flush().expect("failed to flush file");
}

pub fn bench_arguments_from_file<
    G: KimchiCurve,
    BaseSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    srs: poly_commitment::ipa::SRS<G>,
    seed: String,
) -> (
    ProverIndex<G, OpeningProof<G>>,
    [Vec<G::ScalarField>; COLUMNS],
    Vec<RuntimeTable<G::ScalarField>>,
    Vec<RecursionChallenge<G>>,
)
where
    G::BaseField: PrimeField,
{
    let root_dir = match std::env::var("SERIALISED_CIRCUITS_PATH") {
        Err(_) => {
            // this will return .../kimchi/
            let cargo_root = env!("CARGO_MANIFEST_DIR");
            // Default path is ./kimchi/serialized-test-circuits
            format!("{}/serialised-test-circuits/", cargo_root)
        }
        Ok(x) => x,
    };

    let filename1 = format!("{}/kimchi_input_{}_{}.ser", root_dir, G::NAME, seed);
    let filename2 = format!("{}/kimchi_cs_{}_{}.ser", root_dir, G::NAME, seed);

    let bytes1: Vec<u8> = std::fs::read(filename1.clone())
        .unwrap_or_else(|e| panic!("{}. Couldn't read file: {}", e, filename1));
    let (witness, runtime_tables_as_vec, prev_as_pairs): (
        [Vec<_>; COLUMNS],
        Vec<(u32, Vec<G::ScalarField>)>,
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
    let mut reader2 = BufReader::new(
        File::open(filename2.clone())
            .unwrap_or_else(|e| panic!("{}. Couldn't read file: {}", e, filename2)),
    );
    let cs: ConstraintSystem<G::ScalarField> = rmp_serde::from_read(&mut reader2).unwrap();

    let endo = cs.endo;
    let mut index: ProverIndex<G, OpeningProof<G>> = ProverIndex::create(cs, endo, srs.into());
    index.compute_verifier_index_digest::<BaseSponge>();

    (index, witness, runtime_tables, prev)
}
