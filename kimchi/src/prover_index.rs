//! This module implements the prover index as [ProverIndex].

use crate::{
    alphas::Alphas,
    circuits::{
        constraints::ConstraintSystem,
        expr::{Linearization, PolishToken},
        wires::*,
    },
    curve::KimchiCurve,
    linearization::expr_linearization,
};
use ark_poly::EvaluationDomain;
use commitment_dlog::srs::SRS;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;

/// The index used by the prover
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
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

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,
}
//~spec:endcode

impl<G: KimchiCurve> ProverIndex<G> {
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<G::ScalarField>,
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
            cs.range_check_selector_polys.is_some(),
            cs.lookup_constraint_system
                .as_ref()
                .map(|lcs| &lcs.configuration),
            cs.foreign_field_add_selector_polys.is_some(),
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
        }
    }
}

pub mod testing {
    use super::*;
    use crate::circuits::{
        gate::CircuitGate,
        lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    };
    use commitment_dlog::srs::endos;
    use mina_curves::pasta::{pallas::Pallas, vesta::Vesta, Fp};

    pub fn new_index_for_test_with_lookups(
        gates: Vec<CircuitGate<Fp>>,
        public: usize,
        prev_challenges: usize,
        lookup_tables: Vec<LookupTable<Fp>>,
        runtime_tables: Option<Vec<RuntimeTableCfg<Fp>>>,
    ) -> ProverIndex<Vesta> {
        // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
        let cs = ConstraintSystem::<Fp>::create(gates)
            .lookup(lookup_tables)
            .runtime(runtime_tables)
            .public(public)
            .prev_challenges(prev_challenges)
            .build()
            .unwrap();
        let mut srs = SRS::<Vesta>::create(cs.domain.d1.size());
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<Pallas>();
        ProverIndex::<Vesta>::create(cs, endo_q, srs)
    }
    pub fn new_index_for_test(gates: Vec<CircuitGate<Fp>>, public: usize) -> ProverIndex<Vesta> {
        new_index_for_test_with_lookups(gates, public, 0, vec![], None)
    }
}
