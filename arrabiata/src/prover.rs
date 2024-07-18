//! A prover for the Nova recursive SNARK.

use crate::proof::Proof;
use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use mina_poseidon::FqSponge;

use crate::witness::Env;

/// Generate a proof for the IVC circuit.
/// All the information to make a proof is available in the environment given in
/// parameter.
pub fn prove<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    E1Sponge: FqSponge<Fq, E1, Fp>,
    E2Sponge: FqSponge<Fp, E2, Fq>,
>(
    _env: &Env<Fp, Fq, E1, E2, E1Sponge, E2Sponge>,
) -> Result<Proof, String> {
    unimplemented!()
}
