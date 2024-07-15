use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use mina_poseidon::{constants::SpongeConstants, poseidon::ArithmeticSponge};

use crate::{columns::Column, interpreter::InterpreterEnv};

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    SpongeConfig: SpongeConstants,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
> {
    // FIXME
    pub ivc_accumulator_e1: E1,

    // FIXME
    pub ivc_accumulator_e2: E2,

    // FIXME: must not be an option
    pub sponge_fp: Option<ArithmeticSponge<Fp, SpongeConfig>>,

    /// List of public inputs, used first to verify the consistency of the
    /// previous iteration.
    pub current_iteration: u64,

    /// A previous hash, encoded in 2 chunks of 128 bits.
    pub previous_hash: [u128; 2],
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
        E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    > InterpreterEnv for Env<Fp, Fq, SpongeConfig, E1, E2>
{
    type Position = Column;

    // FIXME
    type Variable = Fp;

    fn variable(&self, _column: Self::Position) -> Self::Variable {
        todo!();
    }

    // Only constraint
    fn add_constraint(&mut self, _constraint: Self::Variable) {}
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
        E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    > Env<Fp, Fq, SpongeConfig, E1, E2>
{
    pub fn new() -> Self {
        Self {
            ivc_accumulator_e1: E1::zero(),
            ivc_accumulator_e2: E2::zero(),
            sponge_fp: None,
            current_iteration: 0,
            previous_hash: [0; 2],
        }
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
        E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    > Default for Env<Fp, Fq, SpongeConfig, E1, E2>
{
    fn default() -> Self {
        Self::new()
    }
}
