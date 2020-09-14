/*****************************************************************************************************************

This source file tests polynomial commitments, batched openings and
verification of a batch of batched opening proofs of polynomial commitments
with varying URS length

*****************************************************************************************************************/

use algebra::{bn_382::{g::{Affine, Bn_382GParameters}, Fp}, UniformRand, AffineCurve};
use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, OpeningProof, PolyComm}};
use oracle::utils::PolyUtils;

use oracle::FqSponge;
use oracle::sponge::{DefaultFqSponge};
use oracle::poseidon::{PlonkSpongeConstants as SC};

use std::time::{Instant, Duration};
use ff_fft::DensePolynomial;
use colored::Colorize;
use rand_core::OsRng;
use rand::Rng;
use groupmap::GroupMap;

#[test]
fn heterogeneous_batch_commitment_test()
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let max_rounds = 10;
    let size = 1 << max_rounds;
    let srs = SRS::<Affine>::create(size, 0, 0);

    let polys_per_opening = 3;
    let batch_size = 5;

    let batches : Vec<_> = 
        (0..batch_size).map(|i| {
            // TODO: Produce opening proofs with (max_rounds - i) many rounds
            // ..
        }).collect();

    assert!(srs.verify::<DefaultFqSponge<Bn_382GParameters, SC>>
        (
            &group_map,
            &mut proofs,
            rng
        ));
}
