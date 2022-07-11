// Var types for group operations
mod group;

// Var types for polynomial commitments/openings
mod comm;

// Var types for the verifiers challenges
mod challenge;

// Types for evaluating manipulating polynomials inside circuits
pub mod polynomials;

// Implementations of Pickles traits on "Var"
mod var;

mod scalar;

mod passed;

pub use challenge::{FieldChallenge, GLVChallenge};
pub use comm::VarPolyComm;
pub use group::VarPoint;
pub use polynomials::{LagrangePoly, VanishEval, VarEval};
pub use scalar::Scalar;
