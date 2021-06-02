mod combine;
mod qnr_field;
pub use qnr_field::*;
pub mod commitment;
pub mod srs;
use algebra::{bn_382, tweedle};

use curves::pasta;

pub trait CommitmentField: QnrField {}

impl CommitmentField for pasta::Fp {}

impl CommitmentField for pasta::Fq {}

impl CommitmentField for tweedle::Fq {}

impl CommitmentField for tweedle::Fp {}

impl CommitmentField for bn_382::Fp {}

impl CommitmentField for bn_382::Fq {}
