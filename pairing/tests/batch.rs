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
fn batch_commitment_test()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
{
    let rng = &mut OsRng;
    let depth = 500;
    let size = 8;

    // generate sample URS
    let urs = URS::<E>::create
    (
        depth,
        vec![depth-1, depth-2, depth-3],
        size,
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
            Vec<(Vec<(E::G1Affine, E::Fr)>, Option<(E::G1Affine, usize)>)>,
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
                    (len % (depth-2))+1
                }
            ).collect::<Vec<_>>();
            println!("{}{:?}", "sizes: ".bright_cyan(), length);

            let aa = length.iter().map(|s| DensePolynomial::<E::Fr>::rand(s-1,rng)).collect::<Vec<_>>();
            let a = aa.iter().map(|s| s).collect::<Vec<_>>();
            let x = E::Fr::rand(rng);

            let mut start = Instant::now();
            let comm = a.iter().map(|a| urs.commit(&a.clone(), size).unwrap()).collect::<Vec<_>>();
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
                        comm[i].iter().zip(a[i].eval(x, size).iter()).map(|(c, e)| (*c, *e)).collect(),
                        None
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
            rng
        ), true);
        println!("{}{:?}", "verification time: ".green(), start.elapsed());
    }
}
