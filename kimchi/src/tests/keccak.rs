use std::array;

use crate::circuits::{
    constraints::ConstraintSystem,
    gate::CircuitGate,
    polynomials::keccak::{self, OFF},
    wires::Wire,
};
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Pallas, Vesta};
use rand::Rng;

//use super::framework::TestFramework;
type PallasField = <Pallas as AffineCurve>::BaseField;
