//! Mina Schnorr signature scheme
//!
//! An implementation of the singer interface for the Mina signature algorithm
//!
//! Details: <https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md>

extern crate alloc;

use alloc::{boxed::Box, string::String, vec};
use num_bigint::BigUint;

use crate::{
    BaseField, CurvePoint, Hashable, Keypair, NonceMode, PubKey, ScalarField, Signature, Signer,
};
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

/// `BLAKE2b` output size in bytes for nonce derivation.
///
/// Using 256 bits (32 bytes) provides sufficient entropy for deriving
/// a scalar field element after masking the top 2 bits.
const BLAKE2B_OUTPUT_SIZE: usize = 32;

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

/// Internal message structure for Schnorr signature hash computation.
///
/// This struct combines the user's input message with cryptographic context
/// (public key and nonce commitment) to create the hash input for computing
/// the Schnorr signature challenge. It implements [`Hashable`] to be
/// compatible with Mina's Poseidon-based hashing.
///
/// # Schnorr Signature Context
///
/// In the Schnorr signature scheme, the challenge `e` is computed as:
///
/// ```text
/// e = H(input || pub_key_x || pub_key_y || rx)
/// ```
///
/// where:
/// - `input` is the user's message to sign
/// - `pub_key_x`, `pub_key_y` are the signer's public key coordinates
/// - `rx` is the x-coordinate of the nonce commitment point `R = k·G`
///
/// This binding ensures the signature is tied to a specific message, public
/// key, and nonce, preventing various attack vectors.
///
/// # Fields
///
/// - `input`: The original message being signed, implementing [`Hashable`]
/// - `pub_key_x`: X-coordinate of the signer's public key
/// - `pub_key_y`: Y-coordinate of the signer's public key
/// - `rx`: X-coordinate of the nonce commitment point
#[derive(Clone)]
pub struct Message<H: Hashable> {
    /// The original input message to be signed
    input: H,
    /// X-coordinate of the signer's public key
    pub_key_x: BaseField,
    /// Y-coordinate of the signer's public key
    pub_key_y: BaseField,
    /// X-coordinate of the nonce commitment point R = k·G
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
    fn sign(&mut self, kp: &Keypair, input: &H, nonce_mode: NonceMode) -> Signature {
        let k: ScalarField = match nonce_mode {
            NonceMode::Chunked => self.derive_nonce_chunked(kp, input),
            NonceMode::Legacy => self.derive_nonce_legacy(kp, input),
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
    /// Chunked nonce derivation for zkApp transactions.
    ///
    /// This function implements the deterministic nonce derivation algorithm used
    /// by `Message.Chunked` in the OCaml implementation. Use this for zkApp
    /// transactions that need to be compatible with o1js.
    ///
    /// # Compatibility
    ///
    /// This implementation corresponds to `Message.Chunked.derive` in the OCaml
    /// implementation (`src/lib/crypto/signature_lib/schnorr.ml`).
    ///
    /// It is also compatible with the TypeScript o1js implementation:
    /// <https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/signature.ts>
    ///
    /// The private key conversion replicates the "Field.project" method with unpack
    /// from the OCaml implementation, which performs modular reduction when the
    /// scalar field value is larger than the base field modulus.
    ///
    /// # Algorithm
    ///
    /// The nonce derivation follows this process:
    /// 1. Create `ROInput` from: `message || public_key_x || public_key_y || private_key || network_id`
    /// 2. Pack the `ROInput` into fields using Mina's field packing
    /// 3. Convert packed fields to bits (255 bits per field)
    /// 4. Convert bits to bytes for `BLAKE2b` input
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
    /// A deterministic nonce as a scalar field element.
    ///
    /// # Test Vectors
    ///
    /// For test vectors demonstrating this function's usage, see the
    /// `sign_fields_test` in [`tests/signer.rs`](../../tests/signer.rs) which
    /// uses `NonceMode::Chunked`.
    ///
    /// # Security
    ///
    /// This function generates a cryptographically secure, deterministic nonce
    /// that:
    /// - Depends on the private key, public key, message, and network context
    /// - Ensures no two different messages share the same nonce (with the same
    ///   key)
    /// - Is compatible with existing Mina protocol implementations
    ///
    /// # Panics
    ///
    /// Panics if the `BLAKE2b` variable-output hasher cannot be created with
    /// a 32-byte output size (should not happen).
    pub fn derive_nonce_chunked(&self, kp: &Keypair, input: &H) -> ScalarField {
        let mut blake_hasher =
            Blake2bVar::new(BLAKE2B_OUTPUT_SIZE).expect("BLAKE2b output size is valid");

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
            for &byte in &field_bytes {
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
        let mut bytes = [0; BLAKE2B_OUTPUT_SIZE];
        blake_hasher
            .finalize_variable(&mut bytes)
            .expect("incorrect output size");
        bytes[bytes.len() - 1] &= 0b0011_1111;

        ScalarField::from_random_bytes(&bytes[..]).expect("failed to create scalar from bytes")
    }

    /// Legacy nonce derivation for user commands (payments, delegations).
    ///
    /// This function implements the deterministic nonce derivation algorithm used
    /// by `Message.Legacy` in the OCaml implementation. Use this for legacy Mina
    /// transactions (user commands) such as payments and delegations.
    ///
    /// # Compatibility
    ///
    /// This implementation corresponds to `Message.Legacy.derive` in the OCaml
    /// implementation (`src/lib/crypto/signature_lib/schnorr.ml`).
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
    /// # Usage
    ///
    /// Use this method for legacy Mina transactions (user commands) such as
    /// payments and delegations. For zkApp transactions, use
    /// [`derive_nonce_chunked`](Self::derive_nonce_chunked) instead.
    ///
    /// # Differences from `derive_nonce_chunked`
    ///
    /// This method differs from [`derive_nonce_chunked`](Self::derive_nonce_chunked) in several ways:
    /// - Uses direct byte serialization (`roi.to_bytes()`) instead of field
    ///   packing
    /// - Appends private key as scalar field element instead of base field
    ///   element
    /// - Uses full network ID bytes instead of packed single byte
    /// - Does not perform bit-level manipulation for `BLAKE2b` input
    ///
    /// # Security
    ///
    /// This function generates a cryptographically secure, deterministic nonce
    /// that depends on the private key, public key, message, and network
    /// context.
    fn derive_nonce_legacy(&self, kp: &Keypair, input: &H) -> ScalarField {
        let mut blake_hasher =
            Blake2bVar::new(BLAKE2B_OUTPUT_SIZE).expect("BLAKE2b output size is valid");

        let roi = input
            .to_roinput()
            .append_field(kp.public.point().x)
            .append_field(kp.public.point().y)
            .append_scalar(*kp.secret_key().scalar())
            .append_bytes(&self.domain_param.clone().into_bytes());

        blake_hasher.update(&roi.to_bytes());

        let mut bytes = [0; BLAKE2B_OUTPUT_SIZE];
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
