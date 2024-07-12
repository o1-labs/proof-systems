//! Mina Schnorr signature scheme
//!
//! An implementation of the singer interface for the Mina signature algorithm
//!
//! Details: <https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md>

use ark_ec::{
    AffineRepr, // for prime_subgroup_generator()
    CurveGroup,
};
use ark_ff::{
    BigInteger, // for is_even()
    Field,      // for from_random_bytes()
    PrimeField, // for from_repr()
    Zero,
};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use mina_hasher::{self, DomainParameter, Hasher, ROInput};
use std::ops::{Add, Neg};

use crate::{BaseField, CurvePoint, Hashable, Keypair, PubKey, ScalarField, Signature, Signer};

/// Schnorr signer context for the Mina signature algorithm
///
/// For details about the signature algorithm please see the [`schnorr`](crate::schnorr) documentation
pub struct Schnorr<H: Hashable> {
    hasher: Box<dyn Hasher<Message<H>>>,
    domain_param: H::D,
}

#[derive(Clone)]
struct Message<H: Hashable> {
    input: H,
    pub_key_x: BaseField,
    pub_key_y: BaseField,
    rx: BaseField,
}

impl<H: Hashable> Hashable for Message<H> {
    type D = H::D;

    fn to_roinput(&self) -> ROInput {
        self.input
            .to_roinput()
            .append_field(self.pub_key_x)
            .append_field(self.pub_key_y)
            .append_field(self.rx)
    }

    fn domain_string(domain_param: Self::D) -> Option<String> {
        H::domain_string(domain_param)
    }
}

impl<H: 'static + Hashable> Signer<H> for Schnorr<H> {
    fn sign(&mut self, kp: &Keypair, input: &H) -> Signature {
        let k: ScalarField = self.derive_nonce(kp, input);
        let r: CurvePoint = CurvePoint::generator()
            .mul_bigint(k.into_bigint())
            .into_affine();
        let k: ScalarField = if r.y.into_bigint().is_even() { k } else { -k };

        let e: ScalarField = self.message_hash(&kp.public, r.x, input);
        let s: ScalarField = k + e * kp.secret.scalar();

        Signature::new(r.x, s)
    }

    fn verify(&mut self, sig: &Signature, public: &PubKey, input: &H) -> bool {
        let ev: ScalarField = self.message_hash(public, sig.rx, input);

        let sv = CurvePoint::generator()
            .mul_bigint(sig.s.into_bigint())
            .into_affine();
        // Perform addition and infinity check in projective coordinates for performance
        let rv = public.point().mul_bigint(ev.into_bigint()).neg().add(sv);

        if rv.is_zero() {
            return false;
        }

        let rv = rv.into_affine();

        rv.y.into_bigint().is_even() && rv.x == sig.rx
    }
}

pub(crate) fn create_legacy<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    Schnorr::<H> {
        hasher: Box::new(mina_hasher::create_legacy::<Message<H>>(
            domain_param.clone(),
        )),
        domain_param,
    }
}

pub(crate) fn create_kimchi<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    Schnorr::<H> {
        hasher: Box::new(mina_hasher::create_kimchi::<Message<H>>(
            domain_param.clone(),
        )),
        domain_param,
    }
}

impl<H: 'static + Hashable> Schnorr<H> {
    /// This function uses a cryptographic hash function to create a uniformly and
    /// randomly distributed nonce.  It is crucial for security that no two different
    /// messages share the same nonce.
    fn derive_nonce(&self, kp: &Keypair, input: &H) -> ScalarField {
        let mut blake_hasher = Blake2bVar::new(32).unwrap();

        let roi = input
            .to_roinput()
            .append_field(kp.public.point().x)
            .append_field(kp.public.point().y)
            .append_scalar(*kp.secret.scalar())
            .append_bytes(&self.domain_param.clone().into_bytes());

        blake_hasher.update(&roi.to_bytes());

        let mut bytes = [0; 32];
        blake_hasher
            .finalize_variable(&mut bytes)
            .expect("incorrect output size");
        // Drop the top two bits to convert into a scalar field element
        //   N.B. Since the order of Pallas's scalar field p is very close to 2^m
        //   for some m, truncating only creates a tiny amount of bias that should
        //   be insignificant and better than reduction modulo p.
        bytes[bytes.len() - 1] &= 0b0011_1111;

        ScalarField::from_random_bytes(&bytes[..]).expect("failed to create scalar from bytes")
    }

    /// This function uses a cryptographic hash function (based on a sponge construction) to
    /// convert the message to be signed (and some other information) into a uniformly and
    /// randomly distributed scalar field element.  It uses Mina's variant of the Poseidon
    /// SNARK-friendly cryptographic hash function.
    /// Details: <https://github.com/o1-labs/cryptography-rfcs/blob/httpsnapps-notary-signatures/mina/001-poseidon-sponge.md>
    fn message_hash(&mut self, pub_key: &PubKey, rx: BaseField, input: &H) -> ScalarField {
        let schnorr_input = Message::<H> {
            input: input.clone(),
            pub_key_x: pub_key.point().x,
            pub_key_y: pub_key.point().y,
            rx,
        };

        // Squeeze and convert from base field element to scalar field element
        // Since the difference in modulus between the two fields is < 2^125, w.h.p., a
        // random value from one field will fit in the other field.
        ScalarField::from(self.hasher.hash(&schnorr_input).into_bigint())
    }
}
