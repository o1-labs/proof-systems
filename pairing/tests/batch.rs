/*****************************************************************************************************************

This source file tests batch verificaion of batched polynomial commitment opening proofs

*****************************************************************************************************************/

use commitment_pairing::urs::URS;
use commitment_pairing::commitment::{Utils, PolyComm};
use algebra::{PairingEngine, curves::bls12_381::Bls12_381, UniformRand};
use std::time::{Instant, Duration};
use ff_fft::DensePolynomial;
use rand_core::OsRng;
use colored::Colorize;
use rand::Rng;

#[test]
fn batch_commitment_pairing()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
{
    let rng = &mut OsRng;
    let polysize = 500;
    let size = 8;

    // generate sample URS
    let urs = URS::<E>::create
    (
        size,
        (0..size).map(|i| i).collect(),
        rng
    );

    let mut random = rand::thread_rng();

    for i in 0..1
    {
        println!("{}{:?}", "test # ".bright_cyan(), i);

        let mut proofs = Vec::
        <(
            E::Fr,
            E::Fr,
            Vec<(&PolyComm<E::G1Affine>, &Vec<E::Fr>, Option<usize>)>,
            E::G1Affine,
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

        let aa = length.iter().map(|s| DensePolynomial::<E::Fr>::rand(s-1,rng)).collect::<Vec<_>>();
        let a = aa.iter().map(|s| s).collect::<Vec<_>>();
        let x = E::Fr::rand(rng);
        let evals = a.iter().map(|a| a.eval(x, size)).collect::<Vec<_>>();

        let mut start = Instant::now();
        let comm = a.iter().enumerate().map
        (
            |(i, a)|
            urs.commit(&a.clone(), if i%2==0 {None} else {Some(a.coeffs.len())})
        ).collect::<Vec<_>>();
        commit += start.elapsed();

        let mask = E::Fr::rand(rng);
        start = Instant::now();
        let proof = urs.open(aa.iter().map(|s| s).collect::<Vec<_>>(), mask, x);
        open += start.elapsed();

        proofs.push
        ((
            x,
            mask,
            (0..a.len()).map
            (
                |i|
                (
                    &comm[i], &evals[i], if i%2==0 {None} else {Some(a[i].coeffs.len())}
                )
            ).collect::<Vec<_>>(),
            proof,
        ));

        println!("{}{:?}", "commitment time: ".yellow(), commit);
        println!("{}{:?}", "open time: ".magenta(), open);

        let start = Instant::now();
        assert_eq!(urs.verify
        (
            &proofs,
            rng
        ), true);
        println!("{}{:?}", "verification time: ".green(), start.elapsed());
    }
}
