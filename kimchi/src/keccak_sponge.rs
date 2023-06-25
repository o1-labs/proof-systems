use crate::plonk_sponge::FrSponge;
use ark_ec::{short_weierstrass_jacobian::GroupAffine, ModelParameters, SWModelParameters};
use ark_ff::{fields::FpParameters, BigInteger, PrimeField};
use mina_poseidon::{
    poseidon::ArithmeticSpongeParams,
    sponge::{FqSponge, ScalarChallenge},
};
use std::marker::PhantomData;
use tiny_keccak::{Hasher, Keccak};

/// A sponge designed to be directly compatible with the EVM's Keccak precompile.
#[derive(Debug, Clone)]
struct Keccak256Sponge {
    pending: Vec<u8>,
}

impl Keccak256Sponge {
    /// Create a new cryptographic sponge backed by keccak
    fn new() -> Self {
        Keccak256Sponge { pending: vec![] }
    }

    /// Absorb arbitrary bytes
    fn absorb_bytes(&mut self, x: &[u8]) {
        self.pending.extend(x.iter().map(|x| *x))
    }

    /// Squeeze an output from the sponge
    fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut final_state = Vec::with_capacity(n);
        let mut counter = 0;
        while counter < n {
            // Create a fresh keccak instance, and hash the entire pending contents into `output`.
            let mut hasher = Keccak::v256();
            hasher.update(self.pending.as_slice());
            let mut output = [0u8; 32];
            hasher.finalize(&mut output);

            // Extend the `final_state` buffer with any additional output bytes.
            for i in 0..32 {
                counter += 1;
                if counter >= n {
                    break;
                }
                final_state.push(output[i]);
            }

            // Update the pending state to contain only the current output.
            self.pending = output.to_vec();
        }
        final_state
    }
}

#[derive(Debug, Clone)]
pub struct Keccak256FqSponge<BaseField, G, ScalarField> {
    sponge: Keccak256Sponge,
    _base_field: PhantomData<BaseField>,
    _g: PhantomData<G>,
    _scalar_field: PhantomData<ScalarField>,
}

impl<
        BaseField: PrimeField,
        ScalarField: PrimeField,
        P: SWModelParameters + ModelParameters<ScalarField = ScalarField, BaseField = BaseField>,
    > FqSponge<BaseField, GroupAffine<P>, ScalarField>
    for Keccak256FqSponge<BaseField, GroupAffine<P>, ScalarField>
{
    fn new(_: &'static ArithmeticSpongeParams<BaseField>) -> Self {
        Keccak256FqSponge {
            sponge: Keccak256Sponge::new(),
            _base_field: PhantomData::default(),
            _g: PhantomData::default(),
            _scalar_field: PhantomData::default(),
        }
    }

    fn absorb_g(&mut self, g: &[GroupAffine<P>]) {
        for g in g {
            if g.infinity {
                // absorb a fake point (0, 0)
                let zero = BaseField::zero();
                self.absorb_fq(&[zero, zero]);
            } else {
                self.absorb_fq(&[g.x, g.y]);
            }
        }
    }

    fn absorb_fq(&mut self, x: &[BaseField]) {
        let repr_bytes: usize = (BaseField::Params::MODULUS_BITS as usize + 7) / 8;
        let mut bytes: Vec<u8> = Vec::with_capacity(repr_bytes * x.len());
        for x in x {
            bytes.extend(x.into_repr().to_bytes_be());
        }
        self.sponge.absorb_bytes(bytes.as_slice())
    }

    fn absorb_fr(&mut self, x: &[ScalarField]) {
        let repr_bytes: usize = (ScalarField::Params::MODULUS_BITS as usize + 7) / 8;
        let mut bytes: Vec<u8> = Vec::with_capacity(repr_bytes * x.len());
        for x in x {
            bytes.extend(x.into_repr().to_bytes_be());
        }
        self.sponge.absorb_bytes(bytes.as_slice())
    }

    fn challenge(&mut self) -> ScalarField {
        let repr_bytes: usize = (ScalarField::Params::MODULUS_BITS as usize as usize + 7) / 8;
        ScalarField::from_be_bytes_mod_order(&self.sponge.squeeze(repr_bytes / 2))
    }

    fn challenge_fq(&mut self) -> BaseField {
        let repr_bytes: usize = (BaseField::Params::MODULUS_BITS as usize + 7) / 8;
        BaseField::from_be_bytes_mod_order(&self.sponge.squeeze(repr_bytes / 2))
    }

    fn digest(mut self) -> ScalarField {
        let repr_bytes: usize = (ScalarField::Params::MODULUS_BITS as usize + 7) / 8;
        ScalarField::from_be_bytes_mod_order(&self.sponge.squeeze(repr_bytes))
    }

    fn digest_fq(mut self) -> BaseField {
        let repr_bytes: usize = (BaseField::Params::MODULUS_BITS as usize + 7) / 8;
        BaseField::from_be_bytes_mod_order(&self.sponge.squeeze(repr_bytes))
    }
}

#[derive(Debug, Clone)]
pub struct Keccak256FrSponge<F> {
    sponge: Keccak256Sponge,
    _f: PhantomData<F>,
}

impl<F: PrimeField> FrSponge<F> for Keccak256FrSponge<F> {
    fn new(_: &'static ArithmeticSpongeParams<F>) -> Self {
        Keccak256FrSponge {
            sponge: Keccak256Sponge::new(),
            _f: PhantomData::default(),
        }
    }

    fn absorb_multiple(&mut self, x: &[F]) {
        let repr_bytes: usize = (F::Params::MODULUS_BITS as usize + 7) / 8;
        let mut bytes: Vec<u8> = Vec::with_capacity(repr_bytes * x.len());
        for x in x {
            bytes.extend(x.into_repr().to_bytes_be());
        }
        self.sponge.absorb_bytes(bytes.as_slice())
    }

    fn challenge(&mut self) -> ScalarChallenge<F> {
        let repr_bytes: usize = (F::Params::MODULUS_BITS as usize + 7) / 8;
        ScalarChallenge(F::from_be_bytes_mod_order(
            &self.sponge.squeeze(repr_bytes / 2),
        ))
    }

    fn digest(mut self) -> F {
        let repr_bytes: usize = (F::Params::MODULUS_BITS as usize + 7) / 8;
        F::from_be_bytes_mod_order(&self.sponge.squeeze(repr_bytes))
    }
}
