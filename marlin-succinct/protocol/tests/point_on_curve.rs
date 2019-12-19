/*****************************************************************************************************************

This source file implements Marlin Index unit test suite driver.
The following tests are implemented:

1. Checking Point to be a Group Element
   This test implements the check of whether a point is on an embedded elliptic curve group. The
   Curve constrained computation verifies if an element (given by its Edwards coordinates) belongs to the
   Elliptic Curve group. The test runs the verification that checks that a witness (given by its Edwards
   coordinates) satisfies the constraint equations.

    For the wire labels

    [1, x, y, xx, yy]

    the linear Index is:

    a=[[0,1,0,0,0],[0,0,1,0,0],[0,0,0,d,0]]
    b=[[0,1,0,0,0],[0,0,1,0,0],[0,0,0,0,1]]
    c=[[0,0,0,1,0],[0,0,0,0,1],[-1,0,0,-1,1]]

    The test verifies both positive and negative outcomes for satisfying and not satisfying witnesses

*****************************************************************************************************************/

use circuits::index::Index;
use sprs::{CsMat, CsVecView};
use algebra::{Field, PairingEngine, curves::bls12_381::Bls12_381, UniformRand};
use oracle::poseidon::ArithmeticSpongeParams;
use protocol::prover::ProverProof;
use rand_core::{RngCore, OsRng};
use std::time::Instant;
use colored::Colorize;

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
fn point_on_curve_full()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    // field unity element
    let one = E::Fr::one();
    // field negative unit element
    let neg1 = -one;

    // Jubjub Edwards form coefficient d: y^2-x^2=1+d*y^2*x^2
    let d = <E::Fr as std::str::FromStr>::from_str("19257038036680949359750312669786877991949435402254120286184196891950884077233").unwrap();

    // circuit cinstraint system

    let mut a = CsMat::<E::Fr>::zero((5, 8));
    let mut b = CsMat::<E::Fr>::zero((5, 8));
    let mut c = CsMat::<E::Fr>::zero((5, 8));
    
    a = a
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[1], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[2], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[3], &[d]).unwrap());

    b = b
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[1], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[2], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[4], &[one]).unwrap());

    c = c
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[3], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[4], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[0, 3, 4], &[neg1, neg1, one]).unwrap());

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
    
    let index = Index::<E>::create(a, b, c, 4, oracle_params, rng).unwrap();

    positive::<E>(&index, d, rng);
    negative::<E>(&index, d);
}

fn positive<E: PairingEngine>(index: &Index<E>, d: E::Fr, rng: &mut dyn RngCore)
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    // We have the Index. Choose examples of satisfying witness for Jubjub
    let mut points = Vec::<(E::Fr, E::Fr)>::new();

    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("47847771272602875687997868466650874407263908316223685522183521003714784842376").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("14866155869058627094034298869399931786023896160785945564212907054495032619276").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("23161233924022868901612849355320019731199638537911088707556787060776867075186").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("46827933816106251659874509206068992514697956295153175925290603211849263285943").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("21363808388261502515395491234587106714641012878496416205209487567367794065894").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("35142660575087949075353383974189325596183489114769964645075603269317744401507").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("48251804265475671293065183223958159558134840367204970209791288593670022317146").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("39492112716472193454928048607659273702179031506049462277700522043303788873919").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("26076779737997428048634366966120809315559597005242388987585832521797042997837").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("2916200718278883184735760742052487175592570929008292238193865643072375227389").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("6391827799982489600548224857168349263868938761394485351819740320403055736778").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("26714606321943866209898052587479168369119695309696311252068260485776094410355").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("34225834605492133647358975329540922898558190785910349822925459742326697718965").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("42503065208497349411091392685178794164009360876034587048702740318812028372175").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("39706901109420478047209734657640449984347408718517226120651505259450485889935").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("44842351859583855521445972897388346257004580582454107427806918461747670509399").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("28360026567573852013315702401149784452531421169317971653481741133982080381509").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("34586051224595854378884048103686100857425100914523816028360306191122507857625").unwrap()
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("45719850001957217643735562111452029570487585222534789798311082643976688162166").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("51398963553553644922019770691279615862813421731845531818251689044792926267778").unwrap()
    ));

    println!("{}", "Prover zk-proofs computation".green());
    let mut start = Instant::now();

    let mut batch = Vec::new();
    for i in 0..points.len()
    {
        let (x, y) = points[i];

        // check whether the point is on the curve
        let xx = x*&x;
        let yy = y*&y;
        let yy_xx_1 = yy - &xx - &E::Fr::one();
        let dxx = d * &xx;
        let dxxyy = dxx * &yy;
        assert_eq!(yy_xx_1, dxxyy);

        /*
        the point is on the curve, let's compute the witness and verify the circuit satisfiability
            Wire labels
            [1, x, y, xx, yy]
        */
        let mut witness = vec![E::Fr::zero(); 8];
        witness[0] = E::Fr::one();
        witness[1] = x;
        witness[2] = y;
        witness[3] = xx;
        witness[4] = yy;

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.verify(&witness), true);

        // add the proof to the batch
        batch.push(ProverProof::<E>::create(&witness, &index).unwrap());
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    // verify one proof serially
    match ProverProof::<E>::verify(&vec![batch[0].clone()], &index, rng)
    {
        Ok(_) => {}
        _ => {panic!("Failure verifying the prover's proof")}
    }

    // verify the proofs in batch
    println!("{}", "Verifier zk-proof batch verification".green());
    start = Instant::now();
    match ProverProof::<E>::verify(&batch, &index, rng)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}

fn negative<E: PairingEngine>(index: &Index<E>, d: E::Fr)
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    // field unity element
    let one = E::Fr::one();

    // choose example of non-satisfying assignement for Jubjub
    let x = <E::Fr as std::str::FromStr>::from_str("45719850001957217643735562111452029570487585222534789798311082643976688162166").unwrap();
    let y = <E::Fr as std::str::FromStr>::from_str("51398963553553644922019770691279615862813421731845531818251689044792926267779").unwrap();

    // check whether the point is on the curve
    let xx = x*&x;
    let yy = y*&y;
    let yy_xx_1 = yy - &xx - &one;
    let dxx = d * &xx;
    let dxxyy = dxx * &yy;
    assert_ne!(yy_xx_1, dxxyy);

    let mut witness = vec![E::Fr::zero(); 8];
    witness[0] = one;
    witness[1] = x;
    witness[2] = y;
    witness[3] = xx;
    witness[4] = yy;

    // verify the circuit negative satisfiability by the computed witness
    assert_eq!(index.verify(&witness), false);

    // create proof
    match ProverProof::<E>::create(&witness, &index)
    {
        Ok(_) => {panic!("Failure invalidating the witness")}
        _ => {}
    }
}
