use ark_bn254::g1;
use ark_ec::models::short_weierstrass_jacobian::{GroupAffine, GroupProjective};

pub type Bn254Parameters = g1::Parameters;
pub type Bn254 = GroupAffine<Bn254Parameters>;
pub type ProjectiveBn254 = GroupProjective<Bn254Parameters>;
