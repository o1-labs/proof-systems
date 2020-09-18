mod combine;
mod qnr_field;
pub use qnr_field::*;
pub mod srs;
pub mod commitment;
use algebra::{tweedle, bn_382};

pub trait CommitmentField : QnrField + dlog_solver::DetSquareRootField {
}

impl CommitmentField for tweedle::Fq {
}

impl CommitmentField for tweedle::Fp {
}

impl CommitmentField for bn_382::Fp {
}

impl CommitmentField for bn_382::Fq {
}
