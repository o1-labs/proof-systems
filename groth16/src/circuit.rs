extern crate matrix;

use ark_ff::Field;
use matrix::{format::Compressed, Element};
/// Scalar field of the curve.
pub type Fp = kimchi_msm::Fp;

#[derive(Clone)]
pub struct Circuit<F: Field + Element> {
    pub u: Compressed<F>,
}
