//! secp256k1 curve implementation using ark-secp256k1.
//!
//! This module re-exports types from the ark-secp256k1 crate for use in Mina.
//! secp256k1 is the elliptic curve used in Bitcoin and Ethereum (ECDSA signatures).
//!
//! Curve equation: y^2 = x^3 + 7
//!
//! # Field parameters
//! - Base field modulus (p): 2^256 - 2^32 - 977
//! - Scalar field order (n): 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//!
//! # Usage
//! ```
//! use mina_curves::secp256k1::{Affine, Fq, Fr, Projective, G_GENERATOR_X, G_GENERATOR_Y};
//! use ark_ec::AffineRepr;
//!
//! // Get the generator point
//! let g = Affine::generator();
//! assert!(g.is_on_curve());
//!
//! // Generator coordinates are also available as constants
//! let g_manual = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
//! assert_eq!(g, g_manual);
//! ```

// Re-export all types from ark-secp256k1
pub use ark_secp256k1::{Config, Fq, FqConfig, Fr, FrConfig};

// Re-export curve point types
pub use ark_secp256k1::{Affine, Projective};

/// G_GENERATOR_X =
/// 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
/// = 55066263022277343669578718895168534326250603453777594175500187360389116729240
pub use ark_secp256k1::G_GENERATOR_X;

/// G_GENERATOR_Y =
/// 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
/// = 32670510020758816978083085130507043184471273380659243275938904335757337482424
pub use ark_secp256k1::G_GENERATOR_Y;
