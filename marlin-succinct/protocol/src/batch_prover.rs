/********************************************************************************************

This source file implements batch zk-proof primitive.

This primitive is the top-level aggregate of Marlin zk-proof format that provides means of
optimized batch verification of the individual constituent zk-proofs.

*********************************************************************************************/

use algebra::PairingEngine;
use oracle::rndoracle::ProofError;
use circuits::index::{Index, Witness};
pub use super::prover::ProverProof;

pub struct BatchProof<E: PairingEngine>
{
    pub batch: Vec<Result<ProverProof<E>, ProofError>>
}

impl<E: PairingEngine> BatchProof<E>
{
    // This function constructs batch zk-proof
    //     witness: vector of witness assignements
    //     index: Index
    //     RETURN: zk-proof batch
    pub fn create
    (
        witness: Vec::<Witness::<E::Fr>>,
        index: &Index<E>
    ) -> Self
    {
        // assemble the individual proofs
        BatchProof
        {
            batch: witness.into_iter().map(|w| {ProverProof::create(&w, index)}).collect()
        }
    }
}
