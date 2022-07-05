// Var types for group operations
mod group;

// Var types for polynomial commitments/openings
mod comm;

// Var types for the verifiers challenges
mod challenge;

// Var types related to polynomial (evaluation)
mod polynomials;

mod scalar;

mod passed;

pub use challenge::{FieldChallenge, GLVChallenge};
pub use comm::VarPolyComm;
pub use group::VarPoint;
pub use polynomials::{LagrangePoly, VanishEval, VarEval};
