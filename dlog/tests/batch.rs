/*****************************************************************************************************************

This source file tests polynomial commitments, batched openings and
verification of a batch of batched opening proofs of polynomial commitments

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

type Fr = <Affine as AffineCurve>::ScalarField;

#[test]
fn batch_commitment_test()
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;
    let mut random = rand::thread_rng();

    let size = 1 << 7;
    let polysize = 500;
    let srs = SRS::<Affine>::create(size);

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    for i in 0..2
    {
        println!("{}{:?}", "test # ".bright_cyan(), i);

        let mut proofs = Vec::
        <(
            DefaultFqSponge<Bn_382GParameters, SC>,
            Vec<Fr>,
            Fr,
            Fr,
            Vec<(&PolyComm<Affine>, Vec<&Vec<Fr>>, Option<usize>)>,
            &OpeningProof<Affine>,
        )>::new();

        let mut commit = Duration::new(0, 0);
        let mut open = Duration::new(0, 0);
        
        let length = (0..11).map
        (
            |_|
            {
                let len: usize = random.gen();
                (len % polysize)+1
            }
        ).collect::<Vec<_>>();
        println!("{}{:?}", "sizes: ".bright_cyan(), length);

        let a = length.iter().map(|s| DensePolynomial::<Fr>::rand(s-1,rng)).collect::<Vec<_>>();

        let mut start = Instant::now();
        let comm = (0..a.len()).map
        (
            |i|
            {
                if i%2==0 {srs.commit(&a[i].clone(), Some(a[i].coeffs.len()))}
                else {srs.commit(&a[i].clone(), None)}
            }
        ).collect::<Vec<_>>();
        commit += start.elapsed();

        let x = (0..7).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
        let polymask = Fr::rand(rng);
        let evalmask = Fr::rand(rng);

        let evals = a.iter().map
        (
            |a| x.iter().map(|xx| a.eval(*xx, size)).collect::<Vec<_>>()
        ).collect::<Vec<_>>();

        start = Instant::now();
        let sponge = DefaultFqSponge::<Bn_382GParameters, SC>::new(oracle::bn_382::fp::params());

        let proof = srs.open::<DefaultFqSponge<Bn_382GParameters, SC>>
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
        open += start.elapsed();

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

        println!("{}{:?}", "commitment time: ".yellow(), commit);
        println!("{}{:?}", "open time: ".magenta(), open);

        let start = Instant::now();
        assert_eq!(srs.verify::<DefaultFqSponge<Bn_382GParameters, SC>>
            (
                &group_map,
                &mut proofs,
                rng
            ), true);
        println!("{}{:?}", "verification time: ".green(), start.elapsed());
    }
}
