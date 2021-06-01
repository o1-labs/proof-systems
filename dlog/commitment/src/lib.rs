mod combine;
mod qnr_field;
pub use qnr_field::*;
pub mod commitment;
pub mod srs;
use algebra::pasta;

pub trait CommitmentField: QnrField {}

impl CommitmentField for pasta::Fp {}

impl CommitmentField for pasta::Fq {}
