/*****************************************************************************************************************

This source file tests polynomial commitments, batched openings and
verification of a batch of batched opening proofs of polynomial commitments

*****************************************************************************************************************/

use algebra::{curves::bls12_381::Bls12_381, PairingEngine, UniformRand};
use commitment::{srs::SRS, commitment::OpeningProof};
use oracle::rndoracle::{ArithmeticSpongeParams};
use std::time::{Instant, Duration};
use ff_fft::DensePolynomial;
use colored::Colorize;
use rand_core::OsRng;
use rand::Rng;

// Poseidon MDS Matrix from Vandermonde's A*(B^(-1)) for SPONGE_CAPACITY+SPONGE_RATE=3
pub const MDS: [[&str; 3]; 3] = 
[[
    "6554484396890773809930967563523245729711319062565954727825457337492322648072",
    "13108968793781547619861935127046491459422638125131909455650914674984645296109",
    "32772421984453869049654837817616228648556595312829773639127286687461613240333"
],[
    "32772421984453869049654837817616228648556595312829773639127286687461613240325",
    "13108968793781547619861935127046491459422638125131909455650914674984645296117",
    "6554484396890773809930967563523245729711319062565954727825457337492322648072"
],[
    "6554484396890773809930967563523245729711319062565954727825457337492322648066",
    "13108968793781547619861935127046491459422638125131909455650914674984645296123",
    "32772421984453869049654837817616228648556595312829773639127286687461613240325"
]];

#[test]
fn single_commitment_test()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    // initialise the random oracle argument parameters
    let oracle_params = ArithmeticSpongeParams::<E::Fr>
    {
        round_constants: (0..oracle::poseidon::ROUNDS_FULL+oracle::poseidon::ROUNDS_PARTIAL).map
        (
            |_| (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
            (
                |_| E::Fr::rand(rng)
            ).collect()
        ).collect(),
        mds: (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
        (
            |i| (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
            (
                |j| <E::Fr as std::str::FromStr>::from_str(MDS[i][j]).unwrap()
            ).collect()
        ).collect(),
    };
    
    let mut random = rand::thread_rng();

    let depth = 2000;
    let srs = SRS::<E>::create(depth, rng);

    for i in 0..1
    {
        println!("{}{:?}", "test # ".bright_cyan(), i);

        let mut proofs = Vec::
        <(
            E::Fr,
            E::Fr,
            Vec<(E::G1Affine, E::Fr, usize)>,
            OpeningProof<E>,
        )>::new();

        let mut commit = Duration::new(0, 0);
        let mut open = Duration::new(0, 0);
        
        for _ in 0..3
        {
            let size = (0..3).map
            (
                |_|
                {
                    let len: usize = random.gen();
                    (len % (depth-2))+1
                }
            ).collect::<Vec<_>>();
            println!("{}{:?}", "sizes: ".bright_cyan(), size);

            let a = size.iter().map(|s| (DensePolynomial::<E::Fr>::rand(s-1,rng), *s)).collect::<Vec<_>>();
            let x = E::Fr::rand(rng);

            let mut start = Instant::now();
            let comm = a.iter().map(|a| srs.commit(&a.0.clone(), a.1).unwrap()).collect::<Vec<_>>();
            commit += start.elapsed();

            let mask = E::Fr::rand(rng);
            start = Instant::now();
            let proof = srs.open(&a, mask, x, &oracle_params).unwrap();
            open += start.elapsed();

            proofs.push
            ((
                x,
                mask,
                (0..a.len()).map(|i| (comm[i], a[i].0.evaluate(x), a[i].1)).collect(),
                proof,
            ));
        }

        println!("{}{:?}", "commitment time: ".yellow(), commit);
        println!("{}{:?}", "open time: ".magenta(), open);

        let start = Instant::now();
        assert_eq!(srs.verify
            (
                &proofs,
                &oracle_params,
                rng
            ), true);
        println!("{}{:?}", "verification time: ".green(), start.elapsed());
    }
}
