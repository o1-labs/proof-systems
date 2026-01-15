//! Toy gadgets for testing and examples.
//!
//! These gadgets are NOT intended for use in the NIFS verifier circuit.
//! They demonstrate the gadget API and are used in unit tests.
//!
//! - `TrivialGadget`: No-op gadget (x → x)
//! - `SquaringGadget`: Square input (x → x²)
//! - `CubicGadget`: Cube input (x → x³)
//! - `FibonacciGadget`: Fibonacci step ((a,b) → (b, a+b))
//! - `SquareCubicGadget`: Combined square then cubic
//! - `PlonkishGadget`: Generic Plonkish constraint for testing

mod cubic;
mod fibonacci;
mod plonkish;
mod square_cubic;
mod squaring;
mod trivial;

pub use cubic::CubicGadget;
pub use fibonacci::FibonacciGadget;
pub use plonkish::PlonkishGadget;
pub use square_cubic::{square_cubic_gadget, SquareCubicGadget, SQUARE_CUBIC_ROWS};
pub use squaring::SquaringGadget;
pub use trivial::TrivialGadget;
