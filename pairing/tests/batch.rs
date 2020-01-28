/*****************************************************************************************************************

This source file tests batch verificaion of batched polynomial commitment opening proofs

*****************************************************************************************************************/

use commitment_pairing::urs::URS;
use commitment_pairing::commitment::Utils;
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
            Vec<(Vec<(E::G1Affine, E::Fr)>, Option<(Option<E::G1Affine>, usize)>)>,
            E::G1Affine,
        )>::new();

        let mut commit = Duration::new(0, 0);
        let mut open = Duration::new(0, 0);
        
        for _ in 0..7
        {
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

            let mut start = Instant::now();
            let comm = a.iter().enumerate().map
            (
                |(i, a)|
                urs.commit(&a.clone(), if i%2==0 {None} else {Some(a.coeffs.len())}, size).unwrap()
            ).collect::<Vec<_>>();
            commit += start.elapsed();

            let mask = E::Fr::rand(rng);
            start = Instant::now();
            let proof = urs.open(aa.iter().map(|s| s).collect::<Vec<_>>(), mask, x, size).unwrap();
            open += start.elapsed();

            proofs.push
            ((
                x,
                mask,
                (0..a.len()).map
                (
                    |i|
                    (
                        comm[i].0.iter().zip(a[i].eval(x, size).iter()).map(|(c, e)| (*c, *e)).collect(),
                        if i%2==0 {None} else {Some((comm[i].1, a[i].coeffs.len()))}
                    )
                ).collect::<Vec<_>>(),
                proof,
            ));
        }

        println!("{}{:?}", "commitment time: ".yellow(), commit);
        println!("{}{:?}", "open time: ".magenta(), open);

        let start = Instant::now();
        assert_eq!(urs.verify
        (
            &proofs,
            size,
            rng
        ), true);
        println!("{}{:?}", "verification time: ".green(), start.elapsed());
    }
}
