//! A prover for the folding/accumulation scheme

use crate::{curve::ArrabiataCurve, proof::Proof};
use ark_ff::PrimeField;

use crate::witness::Env;

/// Generate a proof for the IVC circuit.
/// All the information to make a proof is available in the environment given in
/// parameter.
pub fn prove<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    _env: &Env<Fp, Fq, E1, E2>,
) -> Result<Proof, String> {
    unimplemented!()
}
