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

    /// Sponges, index by natural numbers. The natural numbers should be the
    /// instruction.
    /// We keep one sponge state by isntruction and when we merge different
    /// instructions, we can use the different sponges states to compute a new
    /// global one.
    pub sponge_fp: ArithmeticSponge<Fp, SpongeConfig>,

    /// List of public inputs, used first to verify the consistency of the
    /// previous iteration.
    pub current_iteration: usize,

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
}
