//! Test Framework

use crate::{
    circuits::{
        gate::CircuitGate,
        lookup::{
            runtime_tables::{RuntimeTable, RuntimeTableCfg},
            tables::LookupTable,
        },
        wires::COLUMNS,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    proof::{ProverProof, RecursionChallenge},
    prover_index::{testing::new_index_for_test_with_lookups, ProverIndex},
    verifier::verify,
    verifier_index::VerifierIndex,
};
use ark_ff::PrimeField;
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::GroupMap;
use mina_poseidon::sponge::FqSponge;
use num_bigint::BigUint;
use std::{fmt::Write, mem, time::Instant};

// aliases

#[derive(Default)]
pub(crate) struct TestFramework<G: KimchiCurve> {
    gates: Option<Vec<CircuitGate<G::ScalarField>>>,
    witness: Option<[Vec<G::ScalarField>; COLUMNS]>,
    public_inputs: Vec<G::ScalarField>,
    lookup_tables: Vec<LookupTable<G::ScalarField>>,
    runtime_tables_setup: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
    runtime_tables: Vec<RuntimeTable<G::ScalarField>>,
    recursion: Vec<RecursionChallenge<G>>,
    foreign_modulus: Option<BigUint>,
    num_prev_challenges: usize,

    prover_index: Option<ProverIndex<G>>,
    verifier_index: Option<VerifierIndex<G>>,
}

pub(crate) struct TestRunner<G: KimchiCurve>(TestFramework<G>);

impl<G: KimchiCurve> TestFramework<G>
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
{
    #[must_use]
    pub(crate) fn gates(mut self, gates: Vec<CircuitGate<G::ScalarField>>) -> Self {
        self.gates = Some(gates);
        self
    }

    #[must_use]
    pub(crate) fn witness(mut self, witness: [Vec<G::ScalarField>; COLUMNS]) -> Self {
        self.witness = Some(witness);
        self
    }

    #[must_use]
    pub(crate) fn public_inputs(mut self, public_inputs: Vec<G::ScalarField>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    #[must_use]
    pub(crate) fn num_prev_challenges(mut self, num_prev_challenges: usize) -> Self {
        self.num_prev_challenges = num_prev_challenges;
        self
    }

    #[must_use]
    pub(crate) fn lookup_tables(mut self, lookup_tables: Vec<LookupTable<G::ScalarField>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    #[must_use]
    pub(crate) fn foreign_modulus(mut self, modulus: Option<BigUint>) -> Self {
        self.foreign_modulus = modulus;
        self
    }

    #[must_use]
    pub(crate) fn runtime_tables_setup(
        mut self,
        runtime_tables_setup: Vec<RuntimeTableCfg<G::ScalarField>>,
    ) -> Self {
        self.runtime_tables_setup = Some(runtime_tables_setup);
        self
    }

    /// creates the indexes
    #[must_use]
    pub(crate) fn setup(mut self) -> TestRunner<G> {
        let start = Instant::now();

        let lookup_tables = std::mem::take(&mut self.lookup_tables);
        let runtime_tables_setup = mem::replace(&mut self.runtime_tables_setup, None);
        let foreign_modulus_setup = mem::replace(&mut self.foreign_modulus, None);

        let index = new_index_for_test_with_lookups::<G>(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            self.num_prev_challenges,
            lookup_tables,
            runtime_tables_setup,
            foreign_modulus_setup,
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

impl<G: KimchiCurve> TestRunner<G>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
{
    #[must_use]
    pub(crate) fn runtime_tables(
        mut self,
        runtime_tables: Vec<RuntimeTable<G::ScalarField>>,
    ) -> Self {
        self.0.runtime_tables = runtime_tables;
        self
    }

    #[must_use]
    pub(crate) fn recursion(mut self, recursion: Vec<RecursionChallenge<G>>) -> Self {
        self.0.recursion = recursion;
        self
    }

    pub(crate) fn prover_index(&self) -> &ProverIndex<G> {
        self.0.prover_index.as_ref().unwrap()
    }

    /// Create and verify a proof
    pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self)
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    {
        let prover = self.0.prover_index.unwrap();
        let witness = self.0.witness.unwrap();

        // verify the circuit satisfiability by the computed witness
        prover.verify(&witness, &self.0.public_inputs).unwrap();

        // add the proof to the batch
        let start = Instant::now();

        let group_map = <G as CommitmentCurve>::Map::setup();

        let proof = ProverProof::create_recursive::<EFqSponge, EFrSponge>(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
            None,
        )
        .unwrap();
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof
        let start = Instant::now();
        verify::<G, EFqSponge, EFrSponge>(&group_map, &self.0.verifier_index.unwrap(), &proof)
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
            write!(line, "{} | ", bigint).unwrap();
        }
        println!("{line}");
    }
}
