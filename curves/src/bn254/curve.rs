use ark_bn254::g1::{self, G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_ec::models::short_weierstrass_jacobian::{GroupAffine, GroupProjective};

use super::Fq;

pub type Bn254Parameters = g1::Parameters;
pub type Bn254 = GroupAffine<Bn254Parameters>;
pub type ProjectiveBn254 = GroupProjective<Bn254Parameters>;
pub const G_GENERATOR_X: Fq = G1_GENERATOR_X;
pub const G_GENERATOR_Y: Fq = G1_GENERATOR_Y;
