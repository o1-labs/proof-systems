//! Test Framework

// === Macro ===

macro_rules! include_fixture {
    ($name:expr) => {{
        #[cfg(feature = "prover")]
        {
            $name
        }
        #[cfg(not(feature = "prover"))]
        {
            include_bytes!(concat!("fixtures/", $name, ".bin"))
        }
    }};
}
pub(crate) use include_fixture;

// === Common imports ===

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
    verifier_index::VerifierIndex,
};
use alloc::string::{String, ToString};
use ark_ff::PrimeField;
use core::marker::PhantomData;
use groupmap::GroupMap;
use mina_poseidon::{poseidon::ArithmeticSpongeParams, sponge::FqSponge};
use poly_commitment::{
    commitment::CommitmentCurve, ipa::OpeningProof as DlogOpeningProof, OpenProof,
};

// === Prover-only imports ===

#[cfg(feature = "prover")]
use {
    crate::{
        prover_index::{
            testing::{
                new_index_for_test_with_lookups, new_index_for_test_with_lookups_and_custom_srs,
            },
            ProverIndex,
        },
        verifier::verify,
    },
    ark_poly::Radix2EvaluationDomain as D,
    core::fmt::Write,
    num_bigint::BigUint,
    rand_core::{CryptoRng, RngCore},
    std::time::Instant,
};

// === No-prover imports ===

#[cfg(not(feature = "prover"))]
use {
    super::fixtures::RawFixture,
    crate::{linearization::expr_linearization, verifier::verify_with_rng},
    alloc::{sync::Arc, vec::Vec},
    ark_serialize::CanonicalDeserialize,
    poly_commitment::SRS as SrsTrait,
};

// === Heap diagnostics (prover-only) ===

#[cfg(all(
    feature = "prover",
    not(target_arch = "wasm32"),
    feature = "diagnostics"
))]
fn heap_allocated() -> usize {
    use tikv_jemalloc_ctl::{epoch, stats};

    epoch::advance().unwrap();
    stats::allocated::read().unwrap()
}

#[cfg(all(
    feature = "prover",
    any(target_arch = "wasm32", not(feature = "diagnostics"))
))]
fn heap_allocated() -> usize {
    0
}

// === TestFramework ===

#[derive(Default, Clone)]
pub(crate) struct TestFramework<
    const FULL_ROUNDS: usize,
    G: KimchiCurve<FULL_ROUNDS>,
    OpeningProof = DlogOpeningProof<G, FULL_ROUNDS>,
> where
    G::BaseField: PrimeField,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
{
    gates: Option<Vec<CircuitGate<G::ScalarField>>>,
    witness: Option<[Vec<G::ScalarField>; COLUMNS]>,
    public_inputs: Vec<G::ScalarField>,
    lookup_tables: Vec<LookupTable<G::ScalarField>>,
    runtime_tables_setup: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
    runtime_tables: Vec<RuntimeTable<G::ScalarField>>,
    recursion: Vec<RecursionChallenge<G>>,
    num_prev_challenges: usize,
    disable_gates_checks: bool,
    override_srs_size: Option<usize>,
    lazy_mode: bool,
    with_logs: bool,
    _opening_proof: PhantomData<OpeningProof>,

    #[cfg(feature = "prover")]
    prover_index: Option<ProverIndex<FULL_ROUNDS, G, OpeningProof::SRS>>,
    #[cfg(feature = "prover")]
    verifier_index: Option<VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>>,
    #[cfg(feature = "prover")]
    fixture_name: Option<&'static str>,

    #[cfg(not(feature = "prover"))]
    fixture_bytes: Option<&'static [u8]>,
}

// === TestRunner ===

#[derive(Clone)]
pub(crate) struct TestRunner<
    const FULL_ROUNDS: usize,
    G: KimchiCurve<FULL_ROUNDS>,
    OpeningProof = DlogOpeningProof<G, FULL_ROUNDS>,
>(TestFramework<FULL_ROUNDS, G, OpeningProof>)
where
    G::BaseField: PrimeField,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone;

// === Builder methods (both modes) ===

#[allow(dead_code)]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestFramework<FULL_ROUNDS, G, OpeningProof>
where
    G::BaseField: PrimeField,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
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

    #[must_use]
    pub(crate) fn override_srs_size(mut self, size: usize) -> Self {
        self.override_srs_size = Some(size);
        self
    }

    #[must_use]
    pub(crate) fn lazy_mode(mut self, lazy_mode: bool) -> Self {
        self.lazy_mode = lazy_mode;
        self
    }

    pub(crate) fn with_logs(mut self, with_logs: bool) -> Self {
        self.with_logs = with_logs;
        self
    }

    /// Set the fixture for dual-mode prove_and_verify.
    ///
    /// Use with `include_fixture!`:
    /// ```ignore
    /// .fixture(include_fixture!("test_name"))
    /// ```
    ///
    /// With prover: stores the fixture name (for saving).
    /// Without prover: stores the fixture bytes (for loading).
    #[cfg(feature = "prover")]
    #[must_use]
    pub(crate) fn fixture(mut self, name: &'static str) -> Self {
        self.fixture_name = Some(name);
        self
    }

    #[cfg(not(feature = "prover"))]
    #[must_use]
    pub(crate) fn fixture(mut self, bytes: &'static [u8]) -> Self {
        self.fixture_bytes = Some(bytes);
        self
    }

    /// Legacy alias for `.fixture()` in prover mode.
    #[cfg(feature = "prover")]
    #[must_use]
    pub(crate) fn fixture_name(mut self, name: &'static str) -> Self {
        self.fixture_name = Some(name);
        self
    }
}

// === setup() — prover mode ===

#[cfg(feature = "prover")]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestFramework<FULL_ROUNDS, G, OpeningProof>
where
    G::BaseField: PrimeField,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
{
    // Re allow(dead_code): this method is used in tests; without the annotation it warns unnecessarily.
    /// creates the indexes
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn setup_with_custom_srs<F: FnMut(D<G::ScalarField>, usize) -> OpeningProof::SRS>(
        mut self,
        get_srs: F,
    ) -> TestRunner<FULL_ROUNDS, G, OpeningProof> {
        let start = Instant::now();

        let lookup_tables = core::mem::take(&mut self.lookup_tables);
        let runtime_tables_setup = self.runtime_tables_setup.take();

        let index = new_index_for_test_with_lookups_and_custom_srs(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            self.num_prev_challenges,
            lookup_tables,
            runtime_tables_setup,
            self.disable_gates_checks,
            self.override_srs_size,
            get_srs,
            self.lazy_mode,
        );
        println!(
            "- time to create prover index: {:?}s",
            start.elapsed().as_secs()
        );
        if self.with_logs {
            let at_index = heap_allocated();
            println!(
                "- heap after creating prover index: {:?} MB",
                at_index / (1024 * 1024)
            );
        }

        self.verifier_index = Some(index.verifier_index());
        self.prover_index = Some(index);

        TestRunner(self)
    }
}

#[cfg(feature = "prover")]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>> TestFramework<FULL_ROUNDS, G>
where
    G::BaseField: PrimeField,
{
    /// creates the indexes
    #[must_use]
    pub(crate) fn setup(mut self) -> TestRunner<FULL_ROUNDS, G> {
        let start = Instant::now();

        let lookup_tables = core::mem::take(&mut self.lookup_tables);
        let runtime_tables_setup = self.runtime_tables_setup.take();

        let index = new_index_for_test_with_lookups::<FULL_ROUNDS, G>(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            self.num_prev_challenges,
            lookup_tables,
            runtime_tables_setup,
            self.disable_gates_checks,
            self.override_srs_size,
            self.lazy_mode,
        );
        println!(
            "- time to create prover index: {:?}s",
            start.elapsed().as_secs()
        );

        if self.with_logs {
            let bytes = heap_allocated();
            println!(
                "- heap after creating prover index: {:?} MB",
                bytes / (1024 * 1024)
            );
        };

        self.verifier_index = Some(index.verifier_index());
        self.prover_index = Some(index);

        TestRunner(self)
    }
}

// === setup() — no-prover mode (pass-through) ===

#[cfg(not(feature = "prover"))]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>> TestFramework<FULL_ROUNDS, G>
where
    G::BaseField: PrimeField,
{
    #[must_use]
    pub(crate) fn setup(self) -> TestRunner<FULL_ROUNDS, G> {
        TestRunner(self)
    }
}

// === TestRunner methods (both modes) ===

#[allow(dead_code)]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestRunner<FULL_ROUNDS, G, OpeningProof>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
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

    #[must_use]
    pub(crate) fn witness(mut self, witness: [Vec<G::ScalarField>; COLUMNS]) -> Self {
        self.0.witness = Some(witness);
        self
    }
}

// === Prover-only TestRunner methods ===

#[cfg(feature = "prover")]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestRunner<FULL_ROUNDS, G, OpeningProof>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
{
    pub(crate) fn prover_index(&self) -> &ProverIndex<FULL_ROUNDS, G, OpeningProof::SRS> {
        self.0.prover_index.as_ref().unwrap()
    }

    /// Create a proof. This helper can be used when we want to test the prover
    /// raises an exception
    pub(crate) fn prove<EFqSponge, EFrSponge>(self) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
        EFrSponge: FrSponge<G::ScalarField>,
        EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
    {
        let prover = self.0.prover_index.unwrap();
        let witness = self.0.witness.unwrap();

        if !self.0.disable_gates_checks {
            prover
                .verify(&witness, &self.0.public_inputs)
                .map_err(|e| format!("{e:?}"))?;
        }

        let group_map = <G as CommitmentCurve>::Map::setup();

        ProverProof::<G, OpeningProof, FULL_ROUNDS>::create_recursive::<EFqSponge, EFrSponge, _>(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
            None,
            &mut rand::rngs::OsRng,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Create and verify a proof
    pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
        EFrSponge: FrSponge<G::ScalarField>
            + From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
        ProverProof<G, OpeningProof, FULL_ROUNDS>: serde::Serialize,
        VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: serde::Serialize,
    {
        let prover = self.0.prover_index.unwrap();
        let verifier_index = self.0.verifier_index.unwrap();
        let witness = self.0.witness.unwrap();

        if !self.0.disable_gates_checks {
            prover
                .verify(&witness, &self.0.public_inputs)
                .map_err(|e| format!("{e:?}"))?;
        }

        let start = Instant::now();
        let group_map = <G as CommitmentCurve>::Map::setup();

        if self.0.with_logs {
            let bytes = heap_allocated();
            println!(
                "- heap before creating proof: {:?} MB",
                bytes / (1024 * 1024)
            );
        }

        let proof = ProverProof::create_recursive::<EFqSponge, EFrSponge, _>(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
            None,
            &mut rand::rngs::OsRng,
        )
        .map_err(|e| e.to_string())?;
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        if self.0.with_logs {
            let bytes = heap_allocated();
            println!(
                "- heap after creating proof: {:?} MB",
                bytes / (1024 * 1024)
            );
        }

        // verify the proof (propagate any errors)
        let start = Instant::now();
        verify::<FULL_ROUNDS, G, EFqSponge, EFrSponge, OpeningProof>(
            &group_map,
            &verifier_index,
            &proof,
            &self.0.public_inputs,
        )
        .map_err(|e| e.to_string())?;
        println!("- time to verify: {}ms", start.elapsed().as_millis());
        if self.0.with_logs {
            let bytes = heap_allocated();
            println!(
                "- heap after verifying proof: {:?} MB",
                bytes / (1024 * 1024)
            );
        }

        #[cfg(feature = "save-test-proofs")]
        if let Some(name) = self.0.fixture_name {
            use super::fixtures::RawFixture;
            use ark_serialize::CanonicalSerialize;

            let mut public_inputs_buf = Vec::new();
            for fp in &self.0.public_inputs {
                fp.serialize_compressed(&mut public_inputs_buf).unwrap();
            }

            let mut endo_buf = Vec::new();
            verifier_index
                .endo
                .serialize_compressed(&mut endo_buf)
                .unwrap();

            let fixture = RawFixture {
                proof_bytes: rmp_serde::to_vec(&proof).unwrap(),
                verifier_index_bytes: rmp_serde::to_vec(&verifier_index).unwrap(),
                public_inputs_bytes: public_inputs_buf,
                num_public_inputs: self.0.public_inputs.len(),
                feature_flags: prover.cs.feature_flags,
                endo: Some(endo_buf),
            };

            let bytes = rmp_serde::to_vec(&fixture).unwrap();
            let fixtures_dir =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/fixtures");
            std::fs::create_dir_all(&fixtures_dir).unwrap();
            let path = fixtures_dir.join(format!("{name}.bin"));
            std::fs::write(&path, &bytes).unwrap();
            println!("Fixture written to {}", path.display());
        }

        Ok(())
    }
}

// === No-prover prove_and_verify ===

#[cfg(not(feature = "prover"))]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestRunner<FULL_ROUNDS, G, OpeningProof>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
    OpeningProof: OpenProof<G, FULL_ROUNDS>,
    OpeningProof::SRS: SrsTrait<G>,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: Clone,
{
    /// Load a fixture and verify the proof
    pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
        EFrSponge: FrSponge<G::ScalarField>
            + From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
        ProverProof<G, OpeningProof, FULL_ROUNDS>: for<'a> serde::Deserialize<'a>,
        VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS>: for<'a> serde::Deserialize<'a>,
    {
        let bytes = self
            .0
            .fixture_bytes
            .expect("fixture() is required when prover feature is disabled");

        let fixture: RawFixture = rmp_serde::from_slice(bytes).map_err(|e| e.to_string())?;
        let proof: ProverProof<G, OpeningProof, FULL_ROUNDS> =
            rmp_serde::from_slice(&fixture.proof_bytes).map_err(|e| e.to_string())?;
        let mut vi: VerifierIndex<FULL_ROUNDS, G, OpeningProof::SRS> =
            rmp_serde::from_slice(&fixture.verifier_index_bytes).map_err(|e| e.to_string())?;

        let mut public_inputs = Vec::with_capacity(fixture.num_public_inputs);
        let mut cursor = &fixture.public_inputs_bytes[..];
        for _ in 0..fixture.num_public_inputs {
            public_inputs.push(
                G::ScalarField::deserialize_compressed(&mut cursor).map_err(|e| e.to_string())?,
            );
        }

        // Reconstruct serde(skip) fields
        let srs = OpeningProof::SRS::create(vi.max_poly_size);
        srs.get_lagrange_basis(vi.domain);
        vi.srs = Arc::new(srs);

        if let Some(endo_bytes) = &fixture.endo {
            vi.endo = G::ScalarField::deserialize_compressed(&endo_bytes[..])
                .map_err(|e| e.to_string())?;
        }

        let (linearization, powers_of_alpha) =
            expr_linearization(Some(&fixture.feature_flags), true);
        vi.linearization = linearization;
        vi.powers_of_alpha = powers_of_alpha;

        let group_map = <G as CommitmentCurve>::Map::setup();
        verify_with_rng::<FULL_ROUNDS, G, EFqSponge, EFrSponge, OpeningProof, _>(
            &group_map,
            &vi,
            &proof,
            &public_inputs,
            &mut rand::rngs::OsRng,
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    }
}

// === Prover-only serialization regression ===

#[cfg(feature = "prover")]
impl<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, OpeningProof>
    TestRunner<FULL_ROUNDS, G, OpeningProof>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
    OpeningProof: OpenProof<G, FULL_ROUNDS>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + serde::Serialize
        + for<'a> serde::Deserialize<'a>,
    OpeningProof::SRS: Clone,
    VerifierIndex<FULL_ROUNDS, G, OpeningProof>: Clone,
{
    /// Regression test: Create a proof and check that is equal to
    /// the given serialized implementation (and that deserializes
    /// correctly).
    pub(crate) fn prove_and_check_serialization_regression<
        EFqSponge,
        EFrSponge,
        RNG: RngCore + CryptoRng,
    >(
        self,
        buf_expected: Vec<u8>,
        rng: &mut RNG,
    ) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, FULL_ROUNDS>,
        EFrSponge: FrSponge<G::ScalarField>,
        EFrSponge: From<&'static ArithmeticSpongeParams<G::ScalarField, FULL_ROUNDS>>,
    {
        let prover = self.0.prover_index.unwrap();
        let witness = self.0.witness.unwrap();

        if !self.0.disable_gates_checks {
            prover
                .verify(&witness, &self.0.public_inputs)
                .map_err(|e| format!("{e:?}"))?;
        }

        let group_map = <G as CommitmentCurve>::Map::setup();

        let proof = ProverProof::<G, OpeningProof, FULL_ROUNDS>::create_recursive::<
            EFqSponge,
            EFrSponge,
            _,
        >(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
            None,
            rng,
        )
        .map_err(|e| e.to_string())?;

        o1_utils::serialization::test_generic_serialization_regression_serde(proof, buf_expected);

        Ok(())
    }
}

// === print_witness (both modes) ===

#[cfg(feature = "prover")]
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
            write!(line, "{bigint} | ").unwrap();
        }
        println!("{line}");
    }
}
