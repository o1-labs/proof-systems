//! Clone of kimchi/precomputed_srs.rs but for MSM project with BN254

use ark_ff::UniformRand;

use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;

use crate::{Fp, BN254, DOMAIN_SIZE};

/// Obtains an SRS for a specific curve from disk, or generates it if absent.
pub fn get_bn254_srs(domain: EvaluationDomains<Fp>) -> PairingSRS<BN254> {
    // Temporarily just generate it from scratch since SRS serialization is
    // broken.
    let trapdoor = Fp::rand(&mut rand::rngs::OsRng);
    let mut srs = PairingSRS::create(trapdoor, DOMAIN_SIZE);
    srs.full_srs.add_lagrange_basis(domain.d1);
    srs
}
