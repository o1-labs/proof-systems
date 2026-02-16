use ark_algebra_test_templates::*;
use mina_curves::pasta::fields::{Fp as Fr, Fq};

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
