use crate::pasta::ProjectivePallas;
use crate::pasta::ProjectiveVesta;
use ark_algebra_test_templates::*;

test_group!(g1; ProjectivePallas; sw);
test_group!(g2; ProjectiveVesta; sw);
