/*********************************************************************************************************

This source file tests constraints for the Weierstrass curve y^2 = x^3 + 14 group addition
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

use groupmap::GroupMap;
use marlin_protocol_dlog::index::{SRSSpec, Index};
use sprs::{CsMat, CsVecView};
use algebra::{UniformRand, bn_382::g::{Affine, Bn_382GParameters}, AffineCurve, Field, One, Zero};
use marlin_protocol_dlog::{prover::{ProverProof}};
use oracle::{sponge::{DefaultFrSponge, DefaultFqSponge}, poseidon::ArithmeticSpongeParams};
use commitment_dlog::{commitment::{CommitmentCurve, ceil_log2, product, b_poly_coefficients}};
use rand_core::OsRng;
use ff_fft::{DensePolynomial};
use std::time::Instant;
use colored::Colorize;
pub use core::time::Duration;

type Fr = <Affine as AffineCurve>::ScalarField;
const DIMENSION: usize = 1000;

#[test]
fn dlog_marlin_reduction()
{
    // field unity element
    let one = Fr::one();
    // field negative unit element
    let neg1 = -one;

    // our circuit cinstraint system

    let mut a = CsMat::<Fr>::zero((DIMENSION + 5, DIMENSION + 8));
    let mut b = CsMat::<Fr>::zero((DIMENSION + 5, DIMENSION + 8));
    let mut c = CsMat::<Fr>::zero((DIMENSION + 5, DIMENSION + 8));

    for i in 0..DIMENSION-1
    {
        a.insert(i, i, Fr::one());
        b.insert(i, i, Fr::one());
        c.insert(i, i, Fr::one());
        if i%3 == 0
        {
            a.insert(i, i+1, Fr::one());
            b.insert(i, i+1, Fr::one());
            c.insert(i, i+1, Fr::one());
        }
    }
    // This makes the circuit size approximately that, what we are emulating
    
    a = a
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 2], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 3], &[one, neg1]).unwrap());

    b = b
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 7], &[one]).unwrap());

    c = c
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 4, DIMENSION + 5], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 1, DIMENSION + 2, DIMENSION + 3], &[one, one, one]).unwrap())
    .append_outer_csvec(CsVecView::<Fr>::new_view(DIMENSION + 8, &[DIMENSION + 4, DIMENSION + 6], &[one, one]).unwrap());

    let (x1, y1, x2, y2, x3, y3) =
    (
        <Fr as std::str::FromStr>::from_str("3499956327053992311789324315745279077218711522574396611145654815527085555633655891265950097145267897724655566156082").unwrap(),
        <Fr as std::str::FromStr>::from_str("4250726341623352245859193814958075653932439210552578930150640874506143643848176011936425569339283499036976370918547").unwrap(),
        <Fr as std::str::FromStr>::from_str("2277075619467092361075441637545474462708156505551901231294431119215104787945869965412279606012444168553048751531305").unwrap(),
        <Fr as std::str::FromStr>::from_str("5156632548154372308314396817752082262448465615602291512087163669501834087315996859928625857489259758171314588058684").unwrap(),
        <Fr as std::str::FromStr>::from_str("3549623035990464287836624902127543074314683544616644069999418936977157601068501815160870430922313809765697470461011").unwrap(),
        <Fr as std::str::FromStr>::from_str("4149192748600852083475900035990630534222222056341700086574476023821578193169627468582105359207744587896137324600702").unwrap(),
    );
    let s = (y2 - &y1) / &(x2 - &x1);
        
    let mut witness = vec![Fr::zero(); DIMENSION + 8];
    witness[DIMENSION + 0] = Fr::one();
    witness[DIMENSION + 1] = x1;
    witness[DIMENSION + 2] = x2;
    witness[DIMENSION + 3] = x3;
    witness[DIMENSION + 4] = y1;
    witness[DIMENSION + 5] = y2;
    witness[DIMENSION + 6] = y3;
    witness[DIMENSION + 7] = s;

    let mut data: Vec<(usize, Duration, Duration)> = Vec::new();
    for size in (100..200).step_by(100)
    {
        let (p, v) = test(a.clone(), b.clone(), c.clone(), witness.clone(), size);
        data.push((size, p, v));
    }
    println!();
    println!("{}{:?}", "data: ".bright_cyan(), data);
}

fn test
(
    a: CsMat<Fr>,
    b: CsMat<Fr>,
    c: CsMat<Fr>,
    witness: Vec<Fr>,
    srs_size: usize,
) -> (Duration, Duration)
where <Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let index = Index::<Affine>::create
    (
        a,
        b,
        c,
        4,
        srs_size,
        oracle::bn_382::fq::params() as ArithmeticSpongeParams<Fr>,
        oracle::bn_382::fp::params(),
        SRSSpec::Generate
    ).unwrap();

    let mut batch = Vec::new();
    let mut start = Instant::now();

    let prev = {
      let k = ceil_log2(index.srs.get_ref().g.len());
      let chals : Vec<_> = (0..k).map(|_| Fr::rand(rng)).collect();
      let comm = {
          let chal_squareds = chals.iter().map(|x| x.square()).collect::<Vec<_>>();
          let s0 = product(chals.iter().map(|x| *x) ).inverse().unwrap();
          let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(s0, &chal_squareds));
          index.srs.get_ref().commit(&b, None)
      };
      ( chals, comm )
    };

    batch.push(ProverProof::create::<DefaultFqSponge<Bn_382GParameters>, DefaultFrSponge<Fr>>(&group_map, &witness, &index, vec![prev], rng).unwrap());
    let prover_time = start.elapsed();

    let verifier_index = index.verifier_index();
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<Bn_382GParameters>, DefaultFrSponge<Fr>>(&group_map, &batch, &verifier_index, rng)
    {
        false => {panic!("Failure verifying the prover's proofs in batch")},
        true => {}
    }
    let verifier_time = start.elapsed();

    if srs_size == 1000
    {
        println!("{}{:?}", "H domain size: ".magenta(), index.domains.h.size);
        println!("{}{:?}", "K domain size: ".magenta(), index.domains.k.size);
        println!();
    }
    println!("{:?}\t\t\t{:?}\t\t\t{:?}", index.srs.get_ref().g.len(), prover_time, verifier_time);
    (prover_time, verifier_time)
}
