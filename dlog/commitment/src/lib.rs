mod combine;
mod qnr_field;
pub use qnr_field::*;
pub mod commitment;
pub mod srs;

use mina_curves::pasta;

pub trait CommitmentField: QnrField {}

impl CommitmentField for pasta::Fp {}

impl CommitmentField for pasta::Fq {}
