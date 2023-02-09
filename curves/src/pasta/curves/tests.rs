use crate::pasta::pallas::Projective as PallasProjective;
use crate::pasta::vesta::Projective as VestaProjective;
use ark_algebra_test_templates::*;

test_group!(g1; PallasProjective; sw);
test_group!(g2; VestaProjective; sw);
