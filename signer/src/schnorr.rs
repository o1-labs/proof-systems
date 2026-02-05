//! Mina Schnorr signature scheme
//!
//! An implementation of the singer interface for the Mina signature algorithm
//!
//! Details: <https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md>

extern crate alloc;

use alloc::{boxed::Box, string::String, vec};
use num_bigint::BigUint;

use crate::{BaseField, CurvePoint, Hashable, Keypair, PubKey, ScalarField, Signature, Signer};
use ark_ec::{
    AffineRepr, // for generator()
    CurveGroup,
};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use core::ops::{Add, Neg};
use mina_hasher::{self, DomainParameter, Hasher, ROInput};
use o1_utils::FieldHelpers;

/// Schnorr signer context for the Mina signature algorithm
///
/// For details about the signature algorithm please see the
/// [`schnorr`](crate::schnorr) documentation
pub struct Schnorr<H: Hashable> {
    /// The hasher instance used to hash messages
    pub hasher: Box<dyn Hasher<Message<H>>>,
    /// The domain parameter used for hashing
    pub domain_param: H::D,
}

/// The message to be signed/verified
#[derive(Clone)]
pub struct Message<H: Hashable> {
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
    fn sign(&mut self, kp: &Keypair, input: &H, packed: bool) -> Signature {
        let k: ScalarField = match packed {
            true => self.derive_nonce_compatible(kp, input),
            false => self.derive_nonce(kp, input),
        };
        let r: CurvePoint = CurvePoint::generator()
            .mul_bigint(k.into_bigint())
            .into_affine();
        let k: ScalarField = if r.y.into_bigint().is_even() { k } else { -k };

        let e: ScalarField = self.message_hash(&kp.public, r.x, input);
        let s: ScalarField = k + e * kp.secret_key().scalar();

        Signature::new(r.x, s)
    }

    fn verify(&mut self, sig: &Signature, public: &PubKey, input: &H) -> bool {
        let ev: ScalarField = self.message_hash(public, sig.rx, input);

        let sv = CurvePoint::generator()
            .mul_bigint(sig.s.into_bigint())
            .into_affine();
        // Perform addition and infinity check in projective coordinates for
        // performance
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
    /// Derives a nonce compatible with OCaml/TypeScript implementations
    ///
    /// This function implements the deterministic nonce derivation algorithm as
    /// specified in the Mina signature specification:
    /// <https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md>
    ///
    /// # Compatibility
    ///
    /// This implementation is compatible with the TypeScript version:
    /// <https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/signature.ts#L128>
    ///
    /// The private key conversion replicates the "Field.project" method with unpack
    /// from the OCaml implementation, which performs modular reduction when the
    /// scalar field value is larger than the base field modulus.
    ///
    /// # Algorithm
    ///
    /// The nonce derivation follows this process:
    /// 1. Create ROInput from: `message || public_key_x || public_key_y || private_key || network_id`
    /// 2. Pack the ROInput into fields using Mina's field packing
    /// 3. Convert packed fields to bits (255 bits per field)
    /// 4. Convert bits to bytes for BLAKE2b input
    /// 5. Hash with BLAKE2b-256
    /// 6. Drop the top 2 bits to create a valid scalar field element
    ///
    /// # Parameters
    ///
    /// * `kp` - The keypair containing both public and private keys
    /// * `input` - The message to be signed
    ///
    /// # Returns
    ///
    /// A deterministic nonce as a scalar field element, ensuring compatibility
    /// with OCaml and TypeScript signature implementations.
    ///
    /// # Test Vectors
    ///
    /// For test vectors demonstrating this function's usage, see the
    /// `sign_fields_test` in [`tests/signer.rs`](../../tests/signer.rs) which
    /// uses the compatible nonce derivation mode (`packed: true`).
    ///
    /// # Security
    ///
    /// This function generates a cryptographically secure, deterministic nonce
    /// that:
    /// - Depends on the private key, public key, message, and network context
    /// - Ensures no two different messages share the same nonce (with the same
    ///   key)
    /// - Is compatible with existing Mina protocol implementations
    pub fn derive_nonce_compatible(&self, kp: &Keypair, input: &H) -> ScalarField {
        let mut blake_hasher = Blake2bVar::new(32).unwrap();

        // Create ROInput with message + [px, py, private_key_as_field] +
        // network_id_packed
        let network_id_bytes = self.domain_param.clone().into_bytes();
        let network_id_value = if network_id_bytes.is_empty() {
            0u8
        } else {
            network_id_bytes[0]
        };

        let roi = input
            .to_roinput()
            .append_field(kp.public.point().x)
            .append_field(kp.public.point().y)
            .append_field({
                // Convert scalar to base field with explicit wraparound (modular reduction)
                // This replicates the "Field.project" method with unpack from the OCaml implementation

                let secret_biguint: BigUint = kp.secret_key().scalar().into_bigint().into();
                let modulus = BaseField::MODULUS.into();
                if secret_biguint >= modulus {
                    // Reduce modulo base field modulus
                    let reduced_biguint: BigUint = secret_biguint - modulus;
                    BaseField::from_biguint(&reduced_biguint)
                        .expect("Reduced bigint should fit in base field")
                } else {
                    BaseField::from_biguint(&secret_biguint)
                        .expect("Scalar bigint should fit in base field")
                }
            })
            .append_bytes(&[network_id_value]); // Network ID as packed 8 bits

        // Get packed fields
        let packed_fields = roi.to_fields();

        // Convert each field to bits and flatten
        let mut all_bits = vec![];
        for field in packed_fields {
            let field_bytes = field.to_bytes();
            let mut field_bits = 0;
            for &byte in field_bytes.iter() {
                for bit_idx in 0..8 {
                    if field_bits < 255 {
                        let bit = (byte & (1 << bit_idx)) != 0;
                        all_bits.push(bit);
                        field_bits += 1;
                    }
                }
            }
        }

        // Convert bits to bytes for BLAKE2b
        let mut input_bytes = vec![0u8; all_bits.len().div_ceil(8)];
        for (i, &bit) in all_bits.iter().enumerate() {
            if bit {
                input_bytes[i / 8] |= 1 << (i % 8);
            }
        }

        // Hash with BLAKE2b and drop top 2 bits
        blake_hasher.update(&input_bytes);
        let mut bytes = [0; 32];
        blake_hasher
            .finalize_variable(&mut bytes)
            .expect("incorrect output size");
        bytes[bytes.len() - 1] &= 0b0011_1111;

        ScalarField::from_random_bytes(&bytes[..]).expect("failed to create scalar from bytes")
    }

    /// Standard nonce derivation using direct byte serialization
    ///
    /// This function uses a cryptographic hash function to create a uniformly
    /// and randomly distributed nonce. It is crucial for security that no two
    /// different messages share the same nonce.
    ///
    /// # Parameters
    ///
    /// * `kp` - The keypair containing both public and private keys
    /// * `input` - The message to be signed
    ///
    /// # Returns
    ///
    /// A deterministic nonce as a scalar field element.
    ///
    /// # Compatibility
    ///
    /// For OCaml/TypeScript compatibility, use
    /// [`derive_nonce_compatible`](Self::derive_nonce_compatible)
    /// instead. This method will be deprecated in future versions.
    ///
    /// # Differences from `derive_nonce_compatible`
    ///
    /// This method differs from [`derive_nonce_compatible`](Self::derive_nonce_compatible) in several ways:
    /// - Uses direct byte serialization (`roi.to_bytes()`) instead of field
    ///   packing
    /// - Appends private key as scalar field element instead of base field
    ///   element
    /// - Uses full network ID bytes instead of packed single byte
    /// - Does not perform bit-level manipulation for BLAKE2b input
    ///
    /// # Security
    ///
    /// This function generates a cryptographically secure, deterministic nonce
    /// that depends on the private key, public key, message, and network
    /// context.
    fn derive_nonce(&self, kp: &Keypair, input: &H) -> ScalarField {
        let mut blake_hasher = Blake2bVar::new(32).unwrap();

        let roi = input
            .to_roinput()
            .append_field(kp.public.point().x)
            .append_field(kp.public.point().y)
            .append_scalar(*kp.secret_key().scalar())
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

    /// This function uses a cryptographic hash function (based on a sponge
    /// construction) to convert the message to be signed (and some other
    /// information) into a uniformly and randomly distributed scalar field
    /// element. It uses Mina's variant of the Poseidon SNARK-friendly
    /// cryptographic hash function.
    /// Details:
    /// <https://github.com/o1-labs/cryptography-rfcs/blob/httpsnapps-notary-signatures/mina/001-poseidon-sponge.md>
    fn message_hash(&mut self, pub_key: &PubKey, rx: BaseField, input: &H) -> ScalarField {
        let schnorr_input = Message::<H> {
            input: input.clone(),
            pub_key_x: pub_key.point().x,
            pub_key_y: pub_key.point().y,
            rx,
        };

        // Squeeze and convert from base field element to scalar field element
        // Since the difference in modulus between the two fields is < 2^125,
        // w.h.p., a random value from one field will fit in the other field.
        ScalarField::from(self.hasher.hash(&schnorr_input).into_bigint())
    }
}
