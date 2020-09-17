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
    let max_size = 1 << max_rounds;
    let srs = SRS::<Affine>::create(max_size, 0, 0);

    let polys_per_opening = 3;
    let batch_size = 5;

    let rng = &mut OsRng;
    let mut random = rand::thread_rng();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let batches : Vec<_> = 
        (0..batch_size).map(|i| {
            // TODO: Produce opening proofs with (max_rounds - i) many rounds
            // ..
            let mut proofs = Vec::
            <(
                DefaultFqSponge<Bn_382GParameters, SC>,
                Vec<Fr>,
                Fr,
                Fr,
                Vec<(&PolyComm<Affine>, Vec<&Vec<Fr>>, Option<usize>)>,
                &OpeningProof<Affine>,
            )>::new();

            let size = max_rounds - i;

            let srsnew = SRS {g : srs.g[0..(1 << size)], ..*srs};

            let a = (0..3).iter().map(|_| DensePolynomial::<Fr>::rand(size,rng)).collect::<Vec<_>>();
            
            let comm = (0..a.len()).map
            (
                |j|
                {
                    if j%2==0 {srsnew.commit(&a[i].clone(), Some(a[i].coeffs.len()))}
                    else {srsnew.commit(&a[i].clone(), None)}
                }
            ).collect::<Vec<_>>();

            let x = (0..7).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
            let polymask = Fr::rand(rng);
            let evalmask = Fr::rand(rng);

            let evals = a.iter().map
            (
                |a| x.iter().map(|xx| a.eval(*xx, size)).collect::<Vec<_>>()
            ).collect::<Vec<_>>();

            let sponge = DefaultFqSponge::<Bn_382GParameters, SC>::new(oracle::bn_382::fp::params());

            let proof = srsnew.open::<DefaultFqSponge<Bn_382GParameters, SC>>
            (
                &group_map,
                (0..a.len()).map
                (
                    |i| (&a[i], if i%2==0 {Some(a[i].coeffs.len())} else {None})
                ).collect::<Vec<_>>(),
                &x.clone(),
                polymask,
                evalmask,
                sponge.clone(),
                rng,
            );

            proofs.push
            ((
                sponge.clone(),
                x.clone(),
                polymask,
                evalmask,
                (0..a.len()).map
                (
                    |i|
                    (
                        &comm[i],
                        evals[i].iter().map(|evl| evl).collect::<Vec<_>>(),
                        if i%2==0 {Some(a[i].coeffs.len())} else {None})
                    ).collect::<Vec<_>>(),
                &proof,
            ));        
        }).collect();

    assert!(srs.verify::<DefaultFqSponge<Bn_382GParameters, SC>>
        (
            &group_map,
            &mut proofs,
            rng
        ));
}
