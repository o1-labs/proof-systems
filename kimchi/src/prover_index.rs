//! This module implements the prover index as [`ProverIndex`].

use crate::{
    alphas::Alphas,
    circuits::{
        constraints::{ColumnEvaluations, ConstraintSystem},
        expr::{Linearization, PolishToken},
    },
    curve::KimchiCurve,
    linearization::expr_linearization,
    verifier_index::VerifierIndex,
};
use ark_poly::EvaluationDomain;
use mina_poseidon::FqSponge;
use poly_commitment::srs::SRS;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
//~spec:startcode
pub struct ProverIndex<G: KimchiCurve> {
    /// constraints system polynomials
    #[serde(bound = "ConstraintSystem<G::ScalarField>: Serialize + DeserializeOwned")]
    pub cs: ConstraintSystem<G::ScalarField>,

    /// The symbolic linearization of our circuit, which can compile to concrete types once certain values are learned in the protocol.
    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<G::ScalarField>>>,

    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,

    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: Arc<SRS<G>>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    #[serde(bound = "ColumnEvaluations<G::ScalarField>: Serialize + DeserializeOwned")]
    pub column_evaluations: ColumnEvaluations<G::ScalarField>,

    /// The verifier index corresponding to this prover index
    #[serde(skip)]
    pub verifier_index: Option<VerifierIndex<G>>,

    /// The verifier index digest corresponding to this prover index
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub verifier_index_digest: Option<G::BaseField>,
}
//~spec:endcode

impl<G: KimchiCurve> ProverIndex<G> {
    /// this function compiles the index from constraints
    ///
    /// # Panics
    ///
    /// Will panic if `polynomial segment size` is bigger than `circuit`.
    pub fn create(
        mut cs: ConstraintSystem<G::ScalarField>,
        endo_q: G::ScalarField,
        srs: Arc<SRS<G>>,
    ) -> Self {
        let max_poly_size = srs.g.len();
        if cs.public > 0 {
            assert!(
                max_poly_size >= cs.domain.d1.size(),
                "polynomial segment size has to be not smaller than that of the circuit!"
            );
        }
        cs.endo = endo_q;

        // pre-compute the linearization
        let (linearization, powers_of_alpha) = expr_linearization(Some(&cs.feature_flags), true);

        let evaluated_column_coefficients = cs.evaluated_column_coefficients();

        let column_evaluations = cs.column_evaluations(&evaluated_column_coefficients);

        ProverIndex {
            cs,
            linearization,
            powers_of_alpha,
            srs,
            max_poly_size,
            column_evaluations,
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
    ) -> G::BaseField {
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
    ) -> G::BaseField {
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
    use crate::{
        circuits::{
            gate::CircuitGate,
            lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
        },
        precomputed_srs,
    };
    use ark_ff::{PrimeField, SquareRootField};
    use poly_commitment::srs::endos;

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
    ) -> ProverIndex<G>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField + SquareRootField,
    {
        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        let cs = ConstraintSystem::<G::ScalarField>::create(gates)
            .lookup(lookup_tables)
            .runtime(runtime_tables)
            .public(public)
            .prev_challenges(prev_challenges)
            .disable_gates_checks(disable_gates_checks)
            .build()
            .unwrap();

        let mut srs = if cs.domain.d1.log_size_of_group <= precomputed_srs::SERIALIZED_SRS_SIZE {
            // TODO: we should trim it if it's smaller
            precomputed_srs::get_srs()
        } else {
            // TODO: we should resume the SRS generation starting from the serialized one
            SRS::<G>::create(cs.domain.d1.size())
        };

        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<G::OtherCurve>();
        ProverIndex::<G>::create(cs, endo_q, srs)
    }

    pub fn new_index_for_test<G: KimchiCurve>(
        gates: Vec<CircuitGate<G::ScalarField>>,
        public: usize,
    ) -> ProverIndex<G>
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField + SquareRootField,
    {
        new_index_for_test_with_lookups::<G>(gates, public, 0, vec![], None, false)
    }
}
