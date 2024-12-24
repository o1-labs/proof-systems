//! This file aims to test the correctness of the functions from external
//! libraries that are used in the project.
//! It is mostly to ensure that the assumptions we make about the external
//! libraries are correct.

use num_bigint::BigInt;
use num_integer::Integer;

// Testing that modulo on negative numbers gives a positive value.
// It is extensively used in the witness generation, therefore checking this
// assumption is important.
#[test]
fn test_biguint_from_bigint() {
    let a = BigInt::from(-9);
    let modulus = BigInt::from(10);
    let a = a.mod_floor(&modulus);
    assert_eq!(a, BigInt::from(1));
}
