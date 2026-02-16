pub mod capabilities;
pub mod composition;
pub mod constraints;
pub mod witness;

// Reexport main types
pub use crate::circuit_design::{
    capabilities::*,
    composition::{MPrism, SubEnvColumn, SubEnvLookup},
    constraints::ConstraintBuilderEnv,
    witness::WitnessBuilderEnv,
};
