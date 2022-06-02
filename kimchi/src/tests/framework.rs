//! Test Framework

use crate::circuits::lookup::runtime_tables::{RuntimeTable, RuntimeTableCfg};
use crate::circuits::lookup::tables::LookupTable;
use crate::circuits::{gate::CircuitGate, wires::COLUMNS};
use crate::proof::ProverProof;
use crate::prover_index::testing::new_index_for_test_with_lookups;
use crate::prover_index::ProverIndex;
use crate::verifier::verify;
use crate::verifier_index::VerifierIndex;
use ark_ff::PrimeField;
use commitment_dlog::commitment::CommitmentCurve;
use commitment_dlog::PolyComm;
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use num_bigint::BigUint;
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::mem;
use std::time::Instant;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[derive(Default)]
pub(crate) struct TestFramework {
    gates: Option<Vec<CircuitGate<Fp>>>,
    witness: Option<[Vec<Fp>; COLUMNS]>,
    public_inputs: Vec<Fp>,
    lookup_tables: Vec<LookupTable<Fp>>,
    runtime_tables_setup: Option<Vec<RuntimeTableCfg<Fp>>>,
    runtime_tables: Vec<RuntimeTable<Fp>>,
    recursion: Vec<(Vec<Fp>, PolyComm<Affine>)>,

    prover_index: Option<ProverIndex<Affine>>,
    verifier_index: Option<VerifierIndex<Affine>>,
}

pub(crate) struct TestRunner(TestFramework);

impl TestFramework {
    #[must_use]
    pub(crate) fn gates(mut self, gates: Vec<CircuitGate<Fp>>) -> Self {
        self.gates = Some(gates);
        self
    }

    #[must_use]
    pub(crate) fn witness(mut self, witness: [Vec<Fp>; COLUMNS]) -> Self {
        self.witness = Some(witness);
        self
    }

    #[must_use]
    pub(crate) fn public_inputs(mut self, public_inputs: Vec<Fp>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    #[must_use]
    pub(crate) fn lookup_tables(mut self, lookup_tables: Vec<LookupTable<Fp>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    #[must_use]
    pub(crate) fn runtime_tables_setup(
        mut self,
        runtime_tables_setup: Vec<RuntimeTableCfg<Fp>>,
    ) -> Self {
        self.runtime_tables_setup = Some(runtime_tables_setup);
        self
    }

    /// creates the indexes
    #[must_use]
    pub(crate) fn setup(mut self) -> TestRunner {
        let start = Instant::now();

        let lookup_tables = mem::replace(&mut self.lookup_tables, vec![]);
        let runtime_tables_setup = mem::replace(&mut self.runtime_tables_setup, None);

        let index = new_index_for_test_with_lookups(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            lookup_tables,
            runtime_tables_setup,
        );
        println!(
            "- time to create prover index: {:?}s",
            start.elapsed().as_secs()
        );

        self.verifier_index = Some(index.verifier_index());
        self.prover_index = Some(index);

        TestRunner(self)
    }
}

impl TestRunner {
    #[must_use]
    pub(crate) fn runtime_tables(mut self, runtime_tables: Vec<RuntimeTable<Fp>>) -> Self {
        self.0.runtime_tables = runtime_tables;
        self
    }

    #[must_use]
    pub(crate) fn recursion(mut self, recursion: Vec<(Vec<Fp>, PolyComm<Affine>)>) -> Self {
        self.0.recursion = recursion;
        self
    }

    pub(crate) fn prover_index(&self) -> &ProverIndex<Affine> {
        self.0.prover_index.as_ref().unwrap()
    }

    /// Create and verify a proof
    pub(crate) fn prove_and_verify(self) {
        let prover = self.0.prover_index.unwrap();
        let witness = self.0.witness.unwrap();

        // verify the circuit satisfiability by the computed witness
        prover.cs.verify(&witness, &self.0.public_inputs).unwrap();

        // add the proof to the batch
        let start = Instant::now();

        let group_map = <Affine as CommitmentCurve>::Map::setup();

        let proof = ProverProof::create_recursive::<BaseSponge, ScalarSponge>(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
        )
        .unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof
        let start = Instant::now();
        verify::<Affine, BaseSponge, ScalarSponge>(
            &group_map,
            &self.0.verifier_index.unwrap(),
            &proof,
        )
        .unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }
}

pub fn print_witness<F>(cols: &[Vec<F>; COLUMNS], start_row: usize, end_row: usize)
where
    F: PrimeField,
{
    let rows = cols[0].len();
    if start_row > rows || end_row > rows {
        panic!("start_row and end_row are supposed to be in [0, {rows}]");
    }

    for row in start_row..end_row {
        let mut line = "| ".to_string();
        for col in cols {
            let bigint: BigUint = col[row].into();
            line.push_str(&format!("{} | ", bigint));
        }
        println!("{line}");
    }
}
