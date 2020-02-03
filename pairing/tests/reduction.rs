/*********************************************************************************************************

This source file tests constraints for the Weierstrass curve y^2 = x^3 + 7 group addition
of non-special pairs of points

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

    For the variable labeling
    [1, x1, x2, x3, y1, y2, y3, s]

    the Index constraints are

    a=[[0,-1,1,0,0,0,0,0], [0,0,0,0,0,0,0,1], [0,1,0,-1,0,0,0,0]]
    b=[[0,0,0, 0,0,0,0,1], [0,0,0,0,0,0,0,1], [0,0,0,0,0,0,0,1]]
    c=[[0,0,0,0,-1,1,0,0], [0,1,1,1,0,0,0,0], [0,0,0,0,1,0,1,0]]

    The test verifies both positive and negative outcomes for satisfying and not satisfying witnesses

**********************************************************************************************************/

use circuits_pairing::index::{Index, URSSpec};
use sprs::{CsMat, CsVecView};
use oracle::poseidon::ArithmeticSpongeParams;
use protocol_pairing::{prover::{ProverProof}, marlin_sponge::{DefaultFqSponge, DefaultFrSponge}};
use algebra::{curves::{bn_382::{Bn_382, g1::Bn_382G1Parameters}}, fields::{bn_382::fp::Fp, Field}};
use rand_core::OsRng;
use std::time::Instant;
use colored::Colorize;
pub use core::time::Duration;

const DIMENSION: usize = 100000;

#[test]
fn reduction_graph_pairing()
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    // field unity element
    let one = Fp::one();
    // field negative unit element
    let neg1 = -one;

    // our circuit cinstraint system

    let mut a = CsMat::<Fp>::zero((DIMENSION + 5, DIMENSION + 8));
    let mut b = CsMat::<Fp>::zero((DIMENSION + 5, DIMENSION + 8));
    let mut c = CsMat::<Fp>::zero((DIMENSION + 5, DIMENSION + 8));

    for i in 0..DIMENSION-1
    {
        a.insert(i, i, Fp::one());
        b.insert(i, i, Fp::one());
        c.insert(i, i, Fp::one());
        if i%3 == 0
        {
            a.insert(i, i+1, Fp::one());
            b.insert(i, i+1, Fp::one());
            c.insert(i, i+1, Fp::one());
        }
    }

    // This makes the circuit size approximately that, what we are emulating
    
    a = a
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 2], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 3], &[one, neg1]).unwrap());

    b = b
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap());

    c = c
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 4, DIMENSION + 5], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 2, DIMENSION + 3], &[one, one, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fp>::new_view(DIMENSION + 8, &[DIMENSION + 4, DIMENSION + 6], &[one, one]).unwrap());

    let (x1, y1, x2, y2, x3, y3) =
    (
        <Fp as std::str::FromStr>::from_str("5172356774341916945486785014698808798139209652930291469942445827466617176873925086621674152688759641747407229992580").unwrap(),
        <Fp as std::str::FromStr>::from_str("5389835403017389419442092794364295847414750591777998334933723417842844526288891738232423481606681563583908752648585").unwrap(),
        <Fp as std::str::FromStr>::from_str("2546947049417344841111002212494667568252365848624282264487734777527422546757849528444366316986045677524512763495111").unwrap(),
        <Fp as std::str::FromStr>::from_str("1997638122333428225471467658615483900171126775340743769473169439761106892350780308959246670207945253590734533528364").unwrap(),
        <Fp as std::str::FromStr>::from_str("1674850877040352997414732903139735462343308610500259241884671999326597146560061364301738460545828640970450379452180").unwrap(),
        <Fp as std::str::FromStr>::from_str("3810650825927023273265535896307003193230881650215808774887308635589231174623309176102034870088533034962481600516076").unwrap(),
    );
    let s = (y2 - &y1) / &(x2 - &x1);
        
    let mut witness = vec![Fp::zero(); DIMENSION + 8];
    witness[DIMENSION + 0] = Fp::one();
    witness[DIMENSION + 1] = x1;
    witness[DIMENSION + 2] = x2;
    witness[DIMENSION + 3] = x3;
    witness[DIMENSION + 4] = y1;
    witness[DIMENSION + 5] = y2;
    witness[DIMENSION + 6] = y3;
    witness[DIMENSION + 7] = s;

    let mut data: Vec<(usize, Duration, Duration)> = Vec::new();
    for size in (1000..2000).step_by(1000)
    {
        let (p, v) = test(a.clone(), b.clone(), c.clone(), witness.clone(), size);
        data.push((size, p, v));
    }
    println!();
    println!("{}{:?}", "data: ".bright_cyan(), data);
}

fn test
(
    a: CsMat<Fp>,
    b: CsMat<Fp>,
    c: CsMat<Fp>,
    witness: Vec<Fp>,
    srs_size: usize,
) -> (Duration, Duration)
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;
    let index = Index::<Bn_382>::create
    (
        a,
        b,
        c,
        4,
        srs_size,
        oracle::bn_382::fp::params() as ArithmeticSpongeParams<Fp>,
        oracle::bn_382::fq::params(),
        URSSpec::Generate(rng)
    ).unwrap();

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.verify(&witness), true);

    let mut batch = Vec::new();
    let mut start = Instant::now();
    batch.push(ProverProof::create::<DefaultFqSponge<Bn_382G1Parameters>, DefaultFrSponge<Fp>>(&witness, &index).unwrap());
    let prover_time = start.elapsed();

    let verifier_index = index.verifier_index();
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<Bn_382G1Parameters>, DefaultFrSponge<Fp>>(&batch, &verifier_index, rng)
    {
        false => {panic!("Failure verifying the prover's proofs in batch")},
        true => {}
    }
    let verifier_time = start.elapsed();

    if srs_size == 1000
    {
        println!("{}{:?}", "H domain size: ".magenta(), index.domains.h.size());
        println!("{}{:?}", "K domain size: ".magenta(), index.domains.k.size());
        println!();
    }
    println!("{:?}\t\t\t{:?}\t\t\t{:?}", index.urs.get_ref().gp.len(), prover_time, verifier_time);
    (prover_time, verifier_time)
}
