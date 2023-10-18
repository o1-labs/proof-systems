use ark_ec::models::short_weierstrass_jacobian::{GroupAffine, GroupProjective};

pub type Fp = ark_bn254::Fr;
pub type BN254Parameters = ark_bn254::g1::Parameters;
pub type BN254 = GroupAffine<BN254Parameters>;
pub type ProjectiveBN254 = GroupProjective<BN254Parameters>;
