/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::RngCore;
pub use super::index::{VerifierIndex as Index};
use oracle::{FqSponge/*, sponge::ScalarChallenge*/};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{/*Field,*/ AffineCurve};
//use ff_fft::{DensePolynomial, Evaluations};
use crate::plonk_sponge::{FrSponge};
use commitment_dlog::commitment::{CommitmentCurve/*, Utils, PolyComm, b_poly, b_poly_coefficients, products*/};

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct ProofEvals<Fr> {
    pub _x: Fr,
}

impl<G: CommitmentCurve> ProverProof<G>
{
    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     rng: randomness source context
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        _group_map: &G::Map,
        _proofs: &Vec<ProverProof<G>>,
        _index: &Index<G>,
        _rng: &mut dyn RngCore
    ) -> bool
    {
        false
    }
}
