use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;

pub mod columns;
pub mod proof;
pub mod prover;
pub mod verifier;

pub const DOMAIN_SIZE: usize = 1 << 15;

pub type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;

/// The native field we are working with
pub type Fp = ark_bn254::Fr;

pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type OpeningProof = PairingProof<BN254>;

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;

    use crate::{
        proof::Witness, prover::prove, verifier::verify, BaseSponge, Fp, OpeningProof,
        ScalarSponge, BN254,
    };

    #[test]
    fn test_completeness() {
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(&mut rand::rngs::OsRng);

        let mut srs: PairingSRS<BN254> = PairingSRS::create(x, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let witness = Witness::random(domain);

        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, witness);

        // verify the proof
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
        assert!(verifies);
    }
}
