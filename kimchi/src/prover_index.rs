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
use poly_commitment::SRS;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
//~spec:startcode
pub struct ProverIndex<const ROUNDS: usize, G: KimchiCurve<ROUNDS>, Srs> {
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
    pub srs: Arc<Srs>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    #[serde(bound = "ColumnEvaluations<G::ScalarField>: Serialize + DeserializeOwned")]
    pub column_evaluations: Arc<LazyCache<ColumnEvaluations<G::ScalarField>>>,

    /// The verifier index corresponding to this prover index
    #[serde(skip)]
    pub verifier_index: Option<VerifierIndex<ROUNDS, G, Srs>>,

    /// The verifier index digest corresponding to this prover index
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub verifier_index_digest: Option<G::BaseField>,
}
//~spec:endcode

impl<const ROUNDS: usize, G: KimchiCurve<ROUNDS>, Srs: SRS<G>> ProverIndex<ROUNDS, G, Srs>
where
    G::BaseField: PrimeField,
{
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<G::ScalarField>,
        endo_q: G::ScalarField,
        srs: Arc<Srs>,
        lazy_mode: bool,
    ) -> Self {
        let max_poly_size = srs.max_poly_size();
        cs.endo = endo_q;

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
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, ROUNDS>,
    >(
        &mut self,
    ) -> G::BaseField
    where
        VerifierIndex<ROUNDS, G, Srs>: Clone,
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
    pub fn verifier_index_digest<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField, ROUNDS>,
    >(
        &self,
    ) -> G::BaseField
    where
        VerifierIndex<ROUNDS, G, Srs>: Clone,
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
    use poly_commitment::{ipa::OpeningProof, precomputed_srs, OpenProof, SRS};

    #[allow(clippy::too_many_arguments)]
    pub fn new_index_for_test_with_lookups_and_custom_srs<const ROUNDS: usize, G, Srs, F>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<G::ScalarField>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
        disable_gates_checks: bool,
        override_srs_size: Option<usize>,
        mut get_srs: F,
        lazy_mode: bool,
    ) -> ProverIndex<ROUNDS, G, Srs>
    where
        G: KimchiCurve<ROUNDS>,
        Srs: SRS<G>,
        F: FnMut(D<G::ScalarField>, usize) -> Srs,
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
    pub fn new_index_for_test_with_lookups<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<G::ScalarField>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
        disable_gates_checks: bool,
        override_srs_size: Option<usize>,
        lazy_mode: bool,
    ) -> ProverIndex<ROUNDS, G, <OpeningProof<G, ROUNDS> as OpenProof<G, ROUNDS>>::SRS>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        new_index_for_test_with_lookups_and_custom_srs::<ROUNDS, _, _, _>(
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

    pub fn new_index_for_test<const ROUNDS: usize, G: KimchiCurve<ROUNDS>>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
    ) -> ProverIndex<ROUNDS, G, poly_commitment::ipa::SRS<G>>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        new_index_for_test_with_lookups::<ROUNDS, G>(
            gates,
            public,
            0,
            vec![],
            None,
            false,
            None,
            false,
        )
    }
}
