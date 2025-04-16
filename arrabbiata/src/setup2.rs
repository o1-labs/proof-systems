//! This module defines methods and structures for setting up the circuit, or in
//! a more theoretical language, the "NP relation" that the circuit will be
//! related to.
//! Note that when mentioning "circuit" in this context, we are referring to
//! a specific user application in addition to the circuit used to encode the
//! verifier.
//!
//! The setup phase defines the constraints that the computation/the app must
//! satisfy, the evaluation domains, and the SRS for the polynomial commitment
//! scheme. Generally, the setup phase is an agreement between the prover and
//! the verifier on the language and the protocol parameters (cryptographic
//! primitives, security level, etc). The setup phase will also contain some
//! pre-computed values to ease both the prover's and the verifier's work.
//!
//! As part of the setup phase, the parties will also agree on a set of
//! predefined values that will shape the selectors and the computation.
//!
//! A prover will be providing a proof of a particular [IndexedRelation] created
//! during the setup phase, by encapsulating a value of this type in its
//! [crate::witness::Env] structure. The prover will then refer to the values
//! saved in the type [IndexedRelation].
//!
//! On the other side, a verifier will be instantiated with the relevant indexed
//! relation.
//!
use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;
use poly_commitment::{ipa::SRS, PolyComm, SRS as _};
use std::time::Instant;

use crate::{
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    zkapp_registry::{setup, verifier_stateful::Verifier, VerifiableZkApp, ZkApp},
};

/// An indexed relation is a structure that contains all the information needed
/// describing a specialised sub-class of the NP relation. It includes some
/// (protocol) parameters like the SRS, the evaluation domains, and the
/// constraints describing the computation.
///
/// The prover will be instantiated for a particular indexed relation, and the
/// verifier will be instantiated with (relatively) the same indexed relation.
pub struct IndexedRelation<Fp, Fq, E1, E2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<E1::ScalarField>,
    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<E2::ScalarField>,
    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    /// Commitments to the selectors used by both circuits
    pub selectors_comm: (Vec<PolyComm<E1>>, Vec<PolyComm<E2>>),

    /// Initial state of the sponge, containing circuit specific
    /// information.
    pub initial_sponge: Fp,
}

impl<Fp, Fq, E1, E2> IndexedRelation<Fp, Fq, E1, E2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    pub fn new<Z1: ZkApp<E1>, Z2: ZkApp<E2>>(
        zkapp1: &Z1,
        zkapp2: &Z2,
        srs_log2_size: usize,
    ) -> Self {
        let srs_size = 1 << srs_log2_size;

        let domain_fp = EvaluationDomains::<E1::ScalarField>::create(srs_size).unwrap();
        info!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };

        let domain_fq = EvaluationDomains::<E2::ScalarField>::create(srs_size).unwrap();
        info!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        let circuit_zkapp1 = setup(zkapp1);
        let circuit_zkapp2 = setup(zkapp2);

        assert_eq!(circuit_zkapp1.len(), srs_size);
        assert_eq!(circuit_zkapp2.len(), srs_size);

        // FIXME
        let selectors_comm: (Vec<PolyComm<E1>>, Vec<PolyComm<E2>>) = (vec![], vec![]);

        // FIXME: setup correctly the initial sponge state
        let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            core::array::from_fn(|_i| BigInt::from(42u64));

        Self {
            domain_fp,
            srs_e1,
            domain_fq,
            srs_e2,
            selectors_comm,
            initial_sponge: sponge_e1,
        }
    }

    pub fn get_srs_size(&self) -> usize {
        self.domain_fp.d1.size as usize
    }

    pub fn get_srs_blinders(&self) -> (E1, E2) {
        (self.srs_e1.h, self.srs_e2.h)
    }
}
