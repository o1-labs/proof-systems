//! This module implements the prover index as [`ProverIndex`].

use crate::{
    alphas::Alphas,
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        constraints::{ColumnEvaluations, ConstraintSystem},
        expr::{Linearization, PolishToken},
    },
    curve::KimchiCurve,
    linearization::expr_linearization,
    o1_utils::lazy_cache::LazyCache,
    verifier_index::VerifierIndex,
};
use ark_ff::PrimeField;
use mina_poseidon::FqSponge;
use poly_commitment::{OpenProof, SRS as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
//~spec:startcode
pub struct ProverIndex<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    /// constraints system polynomials
    #[serde(bound = "ConstraintSystem<G::ScalarField>: Serialize + DeserializeOwned")]
    pub cs: Arc<ConstraintSystem<G::ScalarField>>,

    /// The symbolic linearization of our circuit, which can compile to concrete types once certain values are learned in the protocol.
    #[serde(skip)]
    pub linearization:
        Linearization<Vec<PolishToken<G::ScalarField, Column, BerkeleyChallengeTerm>>, Column>,

    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,

    /// polynomial commitment keys
    #[serde(skip)]
    #[serde(bound(deserialize = "OpeningProof::SRS: Default"))]
    pub srs: Arc<OpeningProof::SRS>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    #[serde(bound = "ColumnEvaluations<G::ScalarField>: Serialize + DeserializeOwned")]
    pub column_evaluations: Arc<LazyCache<ColumnEvaluations<G::ScalarField>>>,

    /// The verifier index corresponding to this prover index
    #[serde(skip)]
    pub verifier_index: Option<VerifierIndex<G, OpeningProof>>,

    /// The verifier index digest corresponding to this prover index
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub verifier_index_digest: Option<G::BaseField>,
}
//~spec:endcode

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> ProverIndex<G, OpeningProof>
where
    G::BaseField: PrimeField,
{
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<G::ScalarField>,
        endo_q: G::ScalarField,
        srs: Arc<OpeningProof::SRS>,
        lazy_mode: bool,
    ) -> Self {
        let max_poly_size = srs.max_poly_size();
        cs.endo = endo_q;

        // === TEMP TRACE: dump CS gates list to file on index creation ===
        // Gated on `KIMCHI_CS_DUMP` env var. Filename template same shape
        // as `KIMCHI_WITNESS_DUMP`: `%c` is replaced with a monotonic
        // counter (so successive index builds in the same process write
        // to different files). Both kimchi-stubs (OCaml step/wrap
        // compile) and crypto-provider (PS step/wrap compile) funnel
        // through this `ProverIndex::create`, so a single edit here
        // dumps constraint systems on both sides for byte-level diff.
        //
        // Format mirrors the JSON used by circuit-diff fixtures (gates +
        // wires + coeffs + public_input_size). One file per CS.
        if let Ok(path_tmpl) = std::env::var("KIMCHI_CS_DUMP") {
            use ark_poly::EvaluationDomain;
            use std::io::Write;
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = path_tmpl.replace("%c", &counter.to_string());
            let side =
                std::env::var("KIMCHI_CS_DUMP_SIDE").unwrap_or_else(|_| "unknown".to_string());
            if let Ok(mut f) = std::fs::File::create(&path) {
                let _ = writeln!(f, "#side {}", side);
                let _ = writeln!(f, "#counter {}", counter);
                let _ = writeln!(f, "#public_input_size {}", cs.public);
                let _ = writeln!(f, "#prev_challenges {}", cs.prev_challenges);
                let _ = writeln!(f, "#d1_size {}", cs.domain.d1.size());
                let _ = writeln!(f, "#zk_rows {}", cs.zk_rows);
                let _ = writeln!(f, "#max_poly_size {}", max_poly_size);
                let _ = writeln!(f, "#num_gates {}", cs.gates.len());
                // Per-gate dump: kind, wires (col,row pairs), coeffs.
                // One line per gate. Wires are 7 entries (one per
                // permutable column).
                use ark_ff::PrimeField;
                for (i, g) in cs.gates.iter().enumerate() {
                    let wires_str = g
                        .wires
                        .iter()
                        .map(|w| format!("{},{}", w.col, w.row))
                        .collect::<Vec<_>>()
                        .join(";");
                    let coeffs_str = g
                        .coeffs
                        .iter()
                        .map(|c| c.into_bigint().to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let _ = writeln!(
                        f,
                        "g {} kind={:?} wires={} coeffs={}",
                        i, g.typ, wires_str, coeffs_str
                    );
                }
                let _ = f.flush();
            }
        }

        // pre-compute the linearization
        let (linearization, powers_of_alpha) = expr_linearization(Some(&cs.feature_flags), true);

        let evaluated_column_coefficients = cs.evaluated_column_coefficients();

        let cs = Arc::new(cs);
        let cs_clone = Arc::clone(&cs);
        let column_evaluations =
            LazyCache::new(move || cs_clone.column_evaluations(&evaluated_column_coefficients));
        if !lazy_mode {
            // precompute the values
            column_evaluations.get();
        };

        ProverIndex {
            cs,
            linearization,
            powers_of_alpha,
            srs,
            max_poly_size,
            column_evaluations: Arc::new(column_evaluations),
            verifier_index: None,
            verifier_index_digest: None,
        }
    }

    /// Retrieve or compute the digest for the corresponding verifier index.
    /// If the digest is not already cached inside the index, store it.
    pub fn compute_verifier_index_digest<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    >(
        &mut self,
    ) -> G::BaseField
    where
        VerifierIndex<G, OpeningProof>: Clone,
    {
        if let Some(verifier_index_digest) = self.verifier_index_digest {
            return verifier_index_digest;
        }

        if self.verifier_index.is_none() {
            self.verifier_index = Some(self.verifier_index());
        }

        let verifier_index_digest = self.verifier_index_digest::<EFqSponge>();
        self.verifier_index_digest = Some(verifier_index_digest);
        verifier_index_digest
    }

    /// Retrieve or compute the digest for the corresponding verifier index.
    pub fn verifier_index_digest<EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
    ) -> G::BaseField
    where
        VerifierIndex<G, OpeningProof>: Clone,
    {
        if let Some(verifier_index_digest) = self.verifier_index_digest {
            return verifier_index_digest;
        }

        match &self.verifier_index {
            None => {
                let verifier_index = self.verifier_index();
                verifier_index.digest::<EFqSponge>()
            }
            Some(verifier_index) => verifier_index.digest::<EFqSponge>(),
        }
    }
}

pub mod testing {
    use super::*;
    use crate::circuits::{
        gate::CircuitGate,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    };
    use ark_ff::PrimeField;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
    use poly_commitment::{
        ipa::{OpeningProof, SRS},
        precomputed_srs, OpenProof,
    };

    #[allow(clippy::too_many_arguments)]
    pub fn new_index_for_test_with_lookups_and_custom_srs<
        G: KimchiCurve,
        OpeningProof: OpenProof<G>,
        F: FnMut(D<G::ScalarField>, usize) -> OpeningProof::SRS,
    >(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<G::ScalarField>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
        disable_gates_checks: bool,
        override_srs_size: Option<usize>,
        mut get_srs: F,
        lazy_mode: bool,
    ) -> ProverIndex<G, OpeningProof>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        let cs = ConstraintSystem::<G::ScalarField>::create(gates)
            .lookup(lookup_tables)
            .runtime(runtime_tables)
            .public(public)
            .prev_challenges(prev_challenges)
            .disable_gates_checks(disable_gates_checks)
            .max_poly_size(override_srs_size)
            .lazy_mode(lazy_mode)
            .build()
            .unwrap();

        let srs_size = override_srs_size.unwrap_or_else(|| cs.domain.d1.size());
        let srs = get_srs(cs.domain.d1, srs_size);
        let srs = Arc::new(srs);

        let &endo_q = G::other_curve_endo();
        ProverIndex::create(cs, endo_q, srs, lazy_mode)
    }

    /// Create new index for lookups.
    ///
    /// # Panics
    ///
    /// Will panic if `constraint system` is not built with `gates` input.
    pub fn new_index_for_test_with_lookups<G: KimchiCurve>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<G::ScalarField>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
        disable_gates_checks: bool,
        override_srs_size: Option<usize>,
        lazy_mode: bool,
    ) -> ProverIndex<G, OpeningProof<G>>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        new_index_for_test_with_lookups_and_custom_srs(
            gates,
            public,
            prev_challenges,
            lookup_tables,
            runtime_tables,
            disable_gates_checks,
            override_srs_size,
            |d1: D<G::ScalarField>, size: usize| {
                let log2_size = size.ilog2();
                let srs = if log2_size <= precomputed_srs::SERIALIZED_SRS_SIZE {
                    // TODO: we should trim it if it's smaller
                    precomputed_srs::get_srs_test()
                } else {
                    // TODO: we should resume the SRS generation starting from the serialized one
                    SRS::<G>::create(size)
                };

                srs.get_lagrange_basis(d1);
                srs
            },
            lazy_mode,
        )
    }

    pub fn new_index_for_test<G: KimchiCurve>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
    ) -> ProverIndex<G, OpeningProof<G>>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        new_index_for_test_with_lookups::<G>(gates, public, 0, vec![], None, false, None, false)
    }
}
