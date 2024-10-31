use ark_algebra_test_templates::*;
use mina_curves::pasta::{ProjectivePallas, ProjectiveVesta};

test_group!(g1; ProjectivePallas; sw);
test_group!(g2; ProjectiveVesta; sw);
