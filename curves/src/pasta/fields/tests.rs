use crate::pasta::fields::{Fp as Fr, Fq};
use ark_algebra_test_templates::*;

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
