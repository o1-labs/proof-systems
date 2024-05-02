/// Main circuit for the IVC for folding
use crate::poseidon::columns::PoseidonColumn;
use ark_ff::{FpParameters, PrimeField};
use kimchi_msm::circuit_design::{ColAccessCap, HybridCopyCap};
use num_bigint::BigUint;
use num_integer::Integer;
