use crate::pasta::Fp as Fpp;
use crate::pasta::Fq;
use ark_algebra_test_templates::*;

test_field!(fpp; Fpp; mont_prime_field);
test_field!(fq; Fq; mont_prime_field);
