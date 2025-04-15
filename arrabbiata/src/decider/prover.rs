//! A prover for the folding/accumulation scheme

use crate::{curve::ArrabbiataCurve, decider::proof::Proof};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use poly_commitment::commitment::CommitmentCurve;

use crate::witness::Env;

/// Generate a proof.
/// All the information to make a proof is available in the environment given in
/// parameter.
pub fn prove<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    _env: &Env<Fp, Fq, E1, E2>,
) -> Result<Proof, String>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    unimplemented!()
}
