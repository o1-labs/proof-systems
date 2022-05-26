//! This module implements the prover index as [ProverIndex].

use crate::alphas::Alphas;
use crate::circuits::{
    constraints::ConstraintSystem,
    expr::{Linearization, PolishToken},
    wires::*,
};
use crate::linearization::expr_linearization;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use o1_utils::types::fields::*;
use oracle::poseidon::ArithmeticSpongeParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
//~spec:startcode
pub struct ProverIndex<G: CommitmentCurve> {
    /// constraints system polynomials
    #[serde(bound = "ConstraintSystem<ScalarField<G>>: Serialize + DeserializeOwned")]
    pub cs: ConstraintSystem<ScalarField<G>>,

    /// The symbolic linearization of our circuit, which can compile to concrete types once certain values are learned in the protocol.
    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<ScalarField<G>>>>,

    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<ScalarField<G>>,

    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: Arc<SRS<G>>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<BaseField<G>>,
}
//~spec:endcode

impl<'a, G: CommitmentCurve> ProverIndex<G>
where
    G::BaseField: PrimeField,
{
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<ScalarField<G>>,
        fq_sponge_params: ArithmeticSpongeParams<BaseField<G>>,
        endo_q: ScalarField<G>,
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
            cs.domain.d1,
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
        lookup_tables: Vec<LookupTable<Fp>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<Fp>>>,
    ) -> ProverIndex<Affine> {
        let fp_sponge_params = oracle::pasta::fp_kimchi::params();

        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        let cs = ConstraintSystem::<Fp>::create(
            gates,
            lookup_tables,
            runtime_tables,
            fp_sponge_params,
            public,
        )
        .unwrap();
        let mut srs = SRS::<Affine>::create(cs.domain.d1.size());
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let fq_sponge_params = oracle::pasta::fq_kimchi::params();
        let (endo_q, _endo_r) = endos::<Other>();
        ProverIndex::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
    }
    pub fn new_index_for_test(gates: Vec<CircuitGate<Fp>>, public: usize) -> ProverIndex<Affine> {
        new_index_for_test_with_lookups(gates, public, vec![], None)
    }
}
