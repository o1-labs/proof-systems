//! A prover for the Nova recursive SNARK.

use crate::proof::Proof;
use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use mina_poseidon::constants::SpongeConstants;

use crate::witness::Env;

/// Generate a proof for the IVC circuit.
/// All the information to make a proof is available in the environment given in
/// parameter.
pub fn prove<
    Fp: PrimeField,
    Fq: PrimeField,
    SpongeConfig: SpongeConstants,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
>(
    _env: &Env<Fp, Fq, SpongeConfig, E1, E2>,
) -> Result<Proof, String> {
    unimplemented!()
}
