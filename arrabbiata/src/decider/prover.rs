//! A prover for the folding/accumulation scheme

use crate::{
    curve::ArrabbiataCurve,
    decider::proof::Proof,
    witness2::Env,
    zkapp_registry::{verifier_stateful::Verifier, VerifiableZkApp},
};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

/// Generate a proof.
/// All the information to make a proof is available in the environment given in
/// parameter.
pub fn prove<Fp, Fq, E1, E2, ZkApp1, ZkApp2>(
    _env: &Env<Fp, Fq, E1, E2, ZkApp1, ZkApp2>,
) -> Result<Proof<Fp, Fq, E1, E2, ZkApp1, ZkApp2>, String>
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
    Result::Ok(Proof::new())
}
