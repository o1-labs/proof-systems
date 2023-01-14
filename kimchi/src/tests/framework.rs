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
use ark_ff::Zero;
use ark_poly::{Evaluations as E, Radix2EvaluationDomain as D};
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
    num_prev_challenges: usize,
    disable_gates_checks: bool,

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
    pub(crate) fn runtime_tables_setup(
        mut self,
        runtime_tables_setup: Vec<RuntimeTableCfg<G::ScalarField>>,
    ) -> Self {
        self.runtime_tables_setup = Some(runtime_tables_setup);
        self
    }

    #[must_use]
    pub(crate) fn disable_gates_checks(mut self, disable_gates_checks: bool) -> Self {
        self.disable_gates_checks = disable_gates_checks;
        self
    }

    /// creates the indexes
    #[must_use]
    pub(crate) fn setup(mut self) -> TestRunner<G> {
        let start = Instant::now();

        let lookup_tables = std::mem::take(&mut self.lookup_tables);
        let runtime_tables_setup = mem::replace(&mut self.runtime_tables_setup, None);

        let mut index = new_index_for_test_with_lookups::<G>(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            self.num_prev_challenges,
            lookup_tables,
            runtime_tables_setup,
        );
        println!(
            "- time to create prover index: {:?}s",
            start.elapsed().as_secs()
        );

        if self.disable_gates_checks {
            Self::zero_gates_selectors(&mut index);
        }

        self.verifier_index = Some(index.verifier_index());
        self.prover_index = Some(index);

        TestRunner(self)
    }

    fn zero_selector(selector: &mut E<G::ScalarField, D<G::ScalarField>>) {
        selector
            .evals
            .iter_mut()
            .for_each(|eval| *eval = G::ScalarField::zero());
    }

    fn is_selector_zero(selector: &E<G::ScalarField, D<G::ScalarField>>) -> bool {
        selector.evals.iter().fold(true, |is_zero, eval| {
            is_zero && *eval == G::ScalarField::zero()
        })
    }

    fn zero_gates_selectors(prover_index: &mut ProverIndex<G>) {
        prover_index
            .column_evaluations
            .coefficients8
            .iter_mut()
            .for_each(|selector| {
                Self::zero_selector(selector);
            });

        // Zero gate selectors
        Self::zero_selector(&mut prover_index.column_evaluations.generic_selector4);
        Self::zero_selector(&mut prover_index.column_evaluations.poseidon_selector8);
        Self::zero_selector(&mut prover_index.column_evaluations.complete_add_selector4);
        Self::zero_selector(&mut prover_index.column_evaluations.mul_selector8);
        Self::zero_selector(&mut prover_index.column_evaluations.emul_selector8);
        Self::zero_selector(&mut prover_index.column_evaluations.endomul_scalar_selector8);

        // Chacha optional
        if let Some(chacha_selectors8) = &mut prover_index.column_evaluations.chacha_selectors8 {
            chacha_selectors8.iter_mut().for_each(|selector| {
                Self::zero_selector(selector);
            })
        }

        // Range check optional
        if let Some(range_check_selectors8) =
            &mut prover_index.column_evaluations.range_check_selectors8
        {
            range_check_selectors8.iter_mut().for_each(|selector| {
                Self::zero_selector(selector);
            })
        }

        // Foreign field addition optional
        if let Some(foreign_field_add_selector8) =
            &mut prover_index.column_evaluations.foreign_field_add_selector8
        {
            Self::zero_selector(foreign_field_add_selector8);
        }

        // Foreign field multiplication optional
        if let Some(foreign_field_mul_selector8) =
            &mut prover_index.column_evaluations.foreign_field_mul_selector8
        {
            Self::zero_selector(foreign_field_mul_selector8);
        }

        // Xor optional
        if let Some(xor_selector8) = &mut prover_index.column_evaluations.xor_selector8 {
            Self::zero_selector(xor_selector8);
        }

        // Rot optional
        if let Some(rot_selector8) = &mut prover_index.column_evaluations.rot_selector8 {
            Self::zero_selector(rot_selector8);
        }
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
    pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    {
        let prover = self.0.prover_index.unwrap();
        let witness = self.0.witness.unwrap();

        if !self.0.disable_gates_checks {
            println!("Framework verify witness");
            // Verify the circuit satisfiability by the computed witness, baring plookups.
            // This is also done by ProverProof::create_recursive::(), but only for development builds
            prover
                .verify(&witness, &self.0.public_inputs)
                .map_err(|e| format!("{:?}", e))?;
        }

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
        .map_err(|e| e.to_string())?;
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof (propagate any errors)
        let start = Instant::now();
        verify::<G, EFqSponge, EFrSponge>(&group_map, &self.0.verifier_index.unwrap(), &proof)
            .map_err(|e| e.to_string())?;
        println!("- time to verify: {}ms", start.elapsed().as_millis());

        Ok(())
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
