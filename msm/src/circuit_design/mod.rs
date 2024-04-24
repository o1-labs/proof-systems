pub mod capabilities;
pub mod constraints;
pub mod witness;

// Reexport main types
pub use crate::circuit_design::{
    capabilities::{ColAccessCap, ColWriteCap, LookupCap},
    constraints::ConstraintBuilderEnv,
    witness::WitnessBuilderEnv,
};
