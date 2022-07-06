//! This module implements the prover index as [ProverIndex].

use crate::alphas::Alphas;
use crate::circuits::{
    constraints::ConstraintSystem,
    expr::{Linearization, PolishToken},
    wires::*,
};
use crate::linearization::expr_linearization;
use crate::verifier_index::VerifierIndex;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use oracle::{poseidon::ArithmeticSpongeParams, FqSponge};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
//~spec:startcode
pub struct ProverIndex<G: CommitmentCurve> {
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

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<G::BaseField>,

    /// The verifier index corresponding to this prover index
    #[serde(skip)]
    pub verifier_index: Option<VerifierIndex<G>>,

    /// The verifier index digest corresponding to this prover index
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub verifier_index_digest: Option<G::BaseField>,
}
//~spec:endcode

impl<'a, G: CommitmentCurve> ProverIndex<G>
where
    G::BaseField: PrimeField,
{
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<G::ScalarField>,
        fq_sponge_params: ArithmeticSpongeParams<G::BaseField>,
        endo_q: G::ScalarField,
        srs: Arc<SRS<G>>,
    ) -> Self {
        let max_poly_size = srs.g.len();
        if cs.public > 0 {
            assert!(
                max_poly_size >= cs.domain.d1.size(),
                "polynomial segment size has to be not smaller that that of the circuit!"
            );
        }
        cs.endo = endo_q;

        // pre-compute the linearization
        let (linearization, powers_of_alpha) = expr_linearization(
            cs.chacha8.is_some(),
            !cs.range_check_selector_polys.is_empty(),
            cs.lookup_constraint_system
                .as_ref()
                .map(|lcs| &lcs.configuration),
        );

        // set `max_quot_size` to the degree of the quotient polynomial,
        // which is obtained by looking at the highest monomial in the sum
        // $$\sum_{i=0}^{PERMUTS} (w_i(x) + \beta k_i x + \gamma)$$
        // where the $w_i(x)$ are of degree the size of the domain.
        let max_quot_size = PERMUTS * cs.domain.d1.size();

        ProverIndex {
            cs,
            linearization,
            powers_of_alpha,
            srs,
            max_poly_size,
            max_quot_size,
            fq_sponge_params,
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

        if let None = &self.verifier_index {
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
    use crate::circuits::{
        gate::CircuitGate,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    };
    use ark_poly::EvaluationDomain;
    use commitment_dlog::srs::endos;
    use mina_curves::pasta::{pallas::Affine as Other, vesta::Affine, Fp};

    pub fn new_index_for_test_with_lookups(
        gates: Vec<CircuitGate<Fp>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<Fp>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<Fp>>>,
    ) -> ProverIndex<Affine> {
        let fp_sponge_params = oracle::pasta::fp_kimchi::params();

        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        let cs = ConstraintSystem::<Fp>::create(gates, fp_sponge_params)
            .lookup(lookup_tables)
            .runtime(runtime_tables)
            .public(public)
            .prev_challenges(prev_challenges)
            .build()
            .unwrap();
        let mut srs = SRS::<Affine>::create(cs.domain.d1.size());
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let fq_sponge_params = oracle::pasta::fq_kimchi::params();
        let (endo_q, _endo_r) = endos::<Other>();
        ProverIndex::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
    }
    pub fn new_index_for_test(gates: Vec<CircuitGate<Fp>>, public: usize) -> ProverIndex<Affine> {
        new_index_for_test_with_lookups(gates, public, 0, vec![], None)
    }
}
