use crate::Sponge;
use kimchi::curve::KimchiCurve;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::PolyComm;

mod example;
mod example_decomposable_folding;
mod example_quadriticization;

type Fp = ark_bn254::Fr;
type Curve = ark_bn254::G1Affine;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

// TODO: get rid of trait Sponge in folding, and use the one from kimchi
impl Sponge<Curve> for BaseSponge {
    fn challenge(absorb: &[PolyComm<Curve>; 2]) -> Fp {
        // This function does not have a &self because it is meant to absorb and
        // squeeze only once
        let mut s = BaseSponge::new(Curve::other_curve_sponge_params());
        s.absorb_g(&absorb[0].elems);
        s.absorb_g(&absorb[1].elems);
        // Squeeze sponge
        let chal = ScalarChallenge(s.challenge());
        let (_, endo_r) = Curve::endos();
        chal.to_field(endo_r)
    }
}
