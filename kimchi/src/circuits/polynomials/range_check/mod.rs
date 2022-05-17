//! Range check gate

mod circuitgates;

pub mod gate;
pub mod witness;

pub use circuitgates::{RangeCheck0, RangeCheck1};
pub use gate::*;
pub use witness::create_witness;
