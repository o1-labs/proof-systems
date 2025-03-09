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
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use mina_poseidon::constants::SpongeConstants;
use mvpoly::{monomials::Sparse, MVPoly};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use std::{collections::HashMap, time::Instant};

use crate::{
    column::Gadget,
    constraint,
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{self, VERIFIER_STARTING_INSTRUCTION},
    MAXIMUM_FIELD_SIZE_IN_BITS, MAX_DEGREE, MV_POLYNOMIAL_ARITY, NUMBER_OF_COLUMNS,
    NUMBER_OF_GADGETS, VERIFIER_CIRCUIT_SIZE,
};

/// An indexed relation is a structure that contains all the information needed
/// describing a specialised sub-class of the NP relation. It includes some
/// (protocol) parameters like the SRS, the evaluation domains, and the
/// constraints describing the computation.
///
/// The prover will be instantiated for a particular indexed relation, and the
/// verifier will be instantiated with (relatively) the same indexed relation.
pub struct IndexedRelation<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<E1::ScalarField>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<E2::ScalarField>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    /// The application size, i.e. the number of rows per accumulation an
    /// application can use.
    ///
    /// Note that the value is the same for both circuits. We do suppose both
    /// SRS are of the same sizes and the verifier circuits are the same.
    pub app_size: usize,

    /// The description of the program, in terms of gadgets.
    /// For now, the program is the same for both curves.
    ///
    /// The number of elements is exactly the size of the SRS.
    pub circuit_gates: Vec<Gadget>,

    /// Commitments to the selectors used by both circuits
    pub selectors_comm: (
        [PolyComm<E1>; NUMBER_OF_GADGETS],
        [PolyComm<E2>; NUMBER_OF_GADGETS],
    ),

    /// The constraints given as multivariate polynomials using the [mvpoly]
    /// library, indexed by the gadget to ease the selection of the constraints
    /// while computing the cross-terms during the accumulation process.
    ///
    /// When the accumulation scheme is implemented, this structure will
    /// probably be subject to changes as the SNARK used for the accumulation
    /// scheme will probably work over expressions used in
    /// [kimchi::circuits::expr]. We leave that for the future, and focus
    /// on the accumulation scheme implementation.
    ///
    /// We keep two sets of constraints for the time being as we might want in
    /// the future to have different circuits for one of the curves, as inspired
    /// by [CycleFold](https://eprint.iacr.org/2023/1192).
    /// In the current design, both circuits are the same and the prover will do
    /// the same job over both curves.
    pub constraints_fp: HashMap<Gadget, Vec<Sparse<Fp, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>,
    pub constraints_fq: HashMap<Gadget, Vec<Sparse<Fq, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>,

    /// Initial state of the sponge, containing circuit specific
    /// information. The sponge is used to perform the Fiat-Shamir
    /// transformation.
    ///
    /// The initial sponge is a condensed representation of all the messages the
    /// prover and verifier have communicated over the wires and agreed upon
    /// before any computation happens - often called the transcript.
    /// For instance, the commitments to the selectors are information available
    /// to both parties before any computation happens, and therefore are part
    /// of the initial transcript.
    pub initial_sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > IndexedRelation<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    pub fn new(srs_log2_size: usize) -> Self {
        assert!(E1::ScalarField::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fp is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
        assert!(Fq::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fq is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
        let modulus_fp = E1::ScalarField::modulus_biguint();
        let alpha = PlonkSpongeConstants::PERM_SBOX;
        assert!(
            (modulus_fp - BigUint::from(1_u64)).gcd(&BigUint::from(alpha)) == BigUint::from(1_u64),
            "The modulus of Fp should be coprime with {alpha}"
        );
        let modulus_fq = E2::ScalarField::modulus_biguint();
        let alpha = PlonkSpongeConstants::PERM_SBOX;
        assert!(
            (modulus_fq - BigUint::from(1_u64)).gcd(&BigUint::from(alpha)) == BigUint::from(1_u64),
            "The modulus of Fq should be coprime with {alpha}"
        );

        let srs_size = 1 << srs_log2_size;
        let domain_fp = EvaluationDomains::<E1::ScalarField>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<E2::ScalarField>::create(srs_size).unwrap();

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

        let constraints_fp: HashMap<
            Gadget,
            Vec<Sparse<E1::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>,
        > = {
            let env: constraint::Env<E1> = constraint::Env::new();
            let constraints = env.get_all_constraints_indexed_by_gadget();
            constraints
                .into_iter()
                .map(|(k, polynomials)| {
                    (
                        k,
                        polynomials
                            .into_iter()
                            .map(|p| Sparse::from_expr(p, Some(NUMBER_OF_COLUMNS)))
                            .collect(),
                    )
                })
                .collect()
        };

        let constraints_fq: HashMap<
            Gadget,
            Vec<Sparse<E2::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>,
        > = {
            let env: constraint::Env<E2> = constraint::Env::new();
            let constraints = env.get_all_constraints_indexed_by_gadget();
            constraints
                .into_iter()
                .map(|(k, polynomials)| {
                    (
                        k,
                        polynomials
                            .into_iter()
                            .map(|p| Sparse::from_expr(p, Some(NUMBER_OF_COLUMNS)))
                            .collect(),
                    )
                })
                .collect()
        };

        // FIXME: note that the app size can be different for both curves. We
        // suppose we have the same circuit on both curves for now.
        let app_size = srs_size - VERIFIER_CIRCUIT_SIZE;

        // Build the selectors for both circuits.
        // FIXME: we suppose we have the same circuit on both curve for now.
        let circuit_gates: Vec<Gadget> = {
            let mut v: Vec<Gadget> = Vec::with_capacity(srs_size);
            // The first [app_size] rows are for the application
            v.extend([Gadget::App].repeat(app_size));

            // Verifier circuit structure
            {
                let mut curr_instruction = VERIFIER_STARTING_INSTRUCTION;
                for _i in 0..VERIFIER_CIRCUIT_SIZE - 1 {
                    v.push(Gadget::from(curr_instruction));
                    curr_instruction = interpreter::fetch_next_instruction(curr_instruction);
                }
                // Additional row for the Poseidon hash
                v.push(Gadget::NoOp);
            }
            assert_eq!(v.len(), srs_size);
            v
        };

        let selectors_comm: (
            [PolyComm<E1>; NUMBER_OF_GADGETS],
            [PolyComm<E2>; NUMBER_OF_GADGETS],
        ) = {
            // We initialize to the blinder to avoid the identity element.
            let init: (
                [PolyComm<E1>; NUMBER_OF_GADGETS],
                [PolyComm<E2>; NUMBER_OF_GADGETS],
            ) = (
                std::array::from_fn(|_| PolyComm::new(vec![srs_e1.h])),
                std::array::from_fn(|_| PolyComm::new(vec![srs_e2.h])),
            );
            // We commit to the selectors using evaluations.
            // As they are supposed to be one or zero, each row adds a small
            // contribution to the commitment.
            // We explicity commit to all gadgets, even if they are not used in
            // this indexed relation.
            circuit_gates
                .iter()
                .enumerate()
                .fold(init, |mut acc, (row, g)| {
                    let i = usize::from(*g);
                    acc.0[i] = &acc.0[i] + &srs_e1.get_lagrange_basis(domain_fp.d1)[row];
                    acc.1[i] = &acc.1[i] + &srs_e2.get_lagrange_basis(domain_fq.d1)[row];
                    acc
                })
        };

        // The initial transcript state, i.e. all the messages the verifier and
        // prover know before any computation, are all the commitments to the
        // selectors for both circuit.
        // We create an initial sponge state by instantiating a sponge on both
        // curves and absorb the corresponding commitments.
        // After that, we squeeze the state of one sponge to absorb in the
        // other.
        // Arbitrarily, we pick the sponge over second curve to output a digest,
        // and we take the state of the sponge over the first curve.
        let mut sponge_e1 = E1::create_new_sponge();
        selectors_comm.0.iter().for_each(|comm| {
            E1::absorb_curve_points(&mut sponge_e1, &comm.chunks);
        });

        let mut sponge_e2 = E2::create_new_sponge();
        selectors_comm.1.iter().for_each(|comm| {
            E2::absorb_curve_points(&mut sponge_e2, &comm.chunks);
        });
        let digest = E2::digest(&mut sponge_e2);
        E1::absorb_fq(&mut sponge_e1, digest);

        // FIXME: this value will be used to initialize both sponge state.
        // However, there is a negligeable probability that values are not in
        // both fields.
        let initial_sponge: Vec<BigInt> = sponge_e1
            .sponge
            .state
            .iter()
            .map(|x| x.to_biguint().into())
            .collect();

        Self {
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            app_size,
            circuit_gates,
            selectors_comm,
            constraints_fp,
            constraints_fq,
            initial_sponge: initial_sponge.try_into().unwrap(),
        }
    }

    pub fn get_srs_size(&self) -> usize {
        self.domain_fp.d1.size as usize
    }

    pub fn get_srs_blinders(&self) -> (E1, E2) {
        (self.srs_e1.h, self.srs_e2.h)
    }
}
