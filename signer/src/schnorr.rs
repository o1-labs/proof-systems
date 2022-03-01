//! Mina Schnorr signature scheme
//!
//! An implementation of the singer interface for the Mina signature algorithm
//!
//! Details: <https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md>

use ark_ec::{
    AffineCurve,     // for prime_subgroup_generator()
    ProjectiveCurve, // for into_affine()
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
use oracle::poseidon::{ArithmeticSponge, Sponge, SpongeConstants};
use std::ops::Neg;

use crate::{
    domain_prefix_to_field, BaseField, CurvePoint, Hashable, Keypair, NetworkId, PubKey, ROInput,
    ScalarField, Signable, Signature, Signer,
};

/// Schnorr signer context for the Mina signature algorithm
///
/// For details about the signature algorithm please see [crate::schnorr]
pub struct Schnorr<SC: SpongeConstants> {
    sponge: ArithmeticSponge<BaseField, SC>,
    network_id: NetworkId,
}

impl<SC: SpongeConstants> Signer for Schnorr<SC> {
    fn sign<S>(&mut self, kp: Keypair, input: S) -> Signature
    where
        S: Signable,
    {
        let k: ScalarField = self.derive_nonce(&kp, input.clone());
        let r: CurvePoint = CurvePoint::prime_subgroup_generator().mul(k).into_affine();
        let k: ScalarField = if r.y.into_repr().is_even() { k } else { -k };

        let e: ScalarField = self.message_hash(&kp.public, r.x, input);
        let s: ScalarField = k + e * kp.secret.into_scalar();

        Signature::new(r.x, s)
    }

    fn verify<S>(&mut self, sig: Signature, public: PubKey, input: S) -> bool
    where
        S: Signable,
    {
        let ev: ScalarField = self.message_hash(&public, sig.rx, input);

        let sv: CurvePoint = CurvePoint::prime_subgroup_generator()
            .mul(sig.s)
            .into_affine();
        // Perform addition and infinity check in projective coordinates for performance
        let rv = public.into_point().mul(ev).neg().add_mixed(&sv);
        if rv.is_zero() {
            return false;
        }
        let rv = rv.into_affine();

        rv.y.into_repr().is_even() && rv.x == sig.rx
    }
}

impl<SC: SpongeConstants> Schnorr<SC> {
    /// Create a new Schnorr signer context for network instance `network_id` using arithmetic sponge defined by `sponge`.
    pub fn new(sponge: ArithmeticSponge<BaseField, SC>, network_id: NetworkId) -> Schnorr<SC> {
        Schnorr::<SC> { sponge, network_id }
    }

    /// This function uses a cryptographic hash function to create a uniformly and
    /// randomly distributed nonce.  It is crucial for security that no two different
    /// messages share the same nonce.
    fn derive_nonce<H>(&self, kp: &Keypair, input: H) -> ScalarField
    where
        H: Hashable,
    {
        let mut hasher = Blake2bVar::new(32).unwrap();

        let mut roi: ROInput = input.to_roinput();
        roi.append_field(kp.public.into_point().x);
        roi.append_field(kp.public.into_point().y);
        roi.append_scalar(kp.secret.into_scalar());
        roi.append_bytes(&[self.network_id.into()]);

        hasher.update(&roi.to_bytes());

        let mut bytes = [0; 32];
        hasher
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
    fn message_hash<S>(&mut self, pub_key: &PubKey, rx: BaseField, input: S) -> ScalarField
    where
        S: Signable,
    {
        let mut roi: ROInput = input.to_roinput();
        roi.append_field(pub_key.into_point().x);
        roi.append_field(pub_key.into_point().y);
        roi.append_field(rx);

        // Set sponge initial state (explicitly init state so signer context can be reused)
        // N.B. Mina sets the sponge's initial state by hashing the input's domain bytes
        self.sponge.reset();
        self.sponge
            .absorb(&[domain_prefix_to_field::<BaseField>(S::domain_string(
                self.network_id,
            ))]);
        self.sponge.squeeze();

        // Absorb random oracle input
        self.sponge.absorb(&roi.to_fields());

        // Squeeze and convert from base field element to scalar field element
        // Since the difference in modulus between the two fields is < 2^125, w.h.p., a
        // random value from one field will fit in the other field.
        ScalarField::from_repr(self.sponge.squeeze().into_repr()).expect("failed to create scalar")
    }
}
