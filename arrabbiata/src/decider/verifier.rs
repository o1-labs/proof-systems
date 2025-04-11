//! A verifier for the folding/accumulation scheme

use crate::{
    curve::ArrabbiataCurve,
    decider::proof::Proof,
    setup2::IndexedRelation,
    zkapp_registry::{verifier_stateful::Verifier, VerifiableZkApp},
};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

/// Verify a proof.

pub fn verify<Fp, Fq, E1, E2, ZkApp1, ZkApp2>(
    _indexed_relation: &IndexedRelation<Fp, Fq, E1, E2, ZkApp1, ZkApp2>,
    _proof: &Proof<Fp, Fq, E1, E2, ZkApp1, ZkApp2>,
) -> Result<(), String>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<E1, Verifier = Verifier<E1>>,
    ZkApp2: VerifiableZkApp<E2, Verifier = Verifier<E2>>,
{
    Ok(())
}
