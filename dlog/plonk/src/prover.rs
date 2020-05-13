/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve};
use oracle::{/*sponge::ScalarChallenge,*/ FqSponge, rndoracle::{ProofError}};
//use ff_fft::{DensePolynomial, Evaluations};
use commitment_dlog::commitment::{CommitmentCurve, PolyComm/*, Utils, OpeningProof, b_poly_coefficients, product*/};
use crate::plonk_sponge::{FrSponge};
pub use super::index::Index;
use rand_core::RngCore;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;
 
#[derive(Clone)]
pub struct ProofEvaluations<Fr> {
    pub _x: Vec<Fr>,
}

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve>
{
    // polynomial commitments
    pub _x: PolyComm<G>,

    // batched commitment opening proofs

    // polynomial evaluations

    // prover's scalars

    // public part of the witness

    // The challenges underlying the optional polynomials folded into the proof
}

impl<G: CommitmentCurve> ProverProof<G>
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        _group_map: &G::Map,
        _witness: &Vec::<Fr<G>>,
        _index: &Index<G>,
        _prev_challenges: Vec< (Vec<Fr<G>>, PolyComm<G>) >,
        _rng: &mut dyn RngCore,
    ) 
    -> Result<Self, ProofError>
    {
        Err(ProofError::ProofCreation)
    }
}

pub struct RandomOracles<F: Field>
{
    pub _x: F,
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        Self
        {
            _x: F::zero(),
        }
    }
}
