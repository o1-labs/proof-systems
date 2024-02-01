use ark_ec::bn::Bn;
use ark_ff::UniformRand;
use poly_commitment::pairing_proof::{PairingProof, PairingSRS};

use kimchi_msm::DOMAIN_SIZE;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};

type Fp = ark_bn254::Fr;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type OpeningProof = PairingProof<Bn<ark_bn254::Parameters>>;

use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::proof::Witness;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;

pub fn main() {
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs = {
        // Trusted setup toxic waste
        let x = Fp::rand(&mut rand::rngs::OsRng);

        let mut srs = PairingSRS::create(x, DOMAIN_SIZE);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    let lookups = vec![];
    let lookup_counters = vec![];
    let witness = Witness::default();
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(
        domain,
        &srs,
        lookups,
        lookup_counters,
        witness,
    );
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Does it verifies? {verifies}")
}
