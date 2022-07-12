// evaluations of (chunked) polynomials
mod eval;

// vanishing polynomial of the domain
mod vanish;

// evaluation of polynomials in lagrange form
mod lagrange;

// shift (X^{|H|}) polynomial
mod shift;

// zero knowledge masking polynomial
mod zkp;

pub use eval::VarEval;
pub use lagrange::LagrangePoly;
pub use shift::ShiftEval;
pub use vanish::VanishEval;
pub use zkp::ZKPEval;
