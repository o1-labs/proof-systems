use mina_curves::pasta;

pub mod chunked;
mod combine;
pub mod commitment;
mod qnr_field;
pub mod srs;

pub use commitment::PolyComm;
pub use qnr_field::*;

// Fields that can be used for commitments

pub trait CommitmentField: QnrField {}

impl CommitmentField for pasta::Fp {}

impl CommitmentField for pasta::Fq {}
