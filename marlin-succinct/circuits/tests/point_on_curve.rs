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

use sprs::{CsMat, CsVecView};
use algebra::{Field, PairingEngine, curves::bls12_381::Bls12_381, UniformRand};
use circuits::{witness::Witness, index::Index};
use oracle::poseidon::ArithmeticSpongeParams;
use rand_core::OsRng;

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

// The following test verifies the polynomial commitment scheme
#[test]
fn point_on_curve()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    // initialise constants
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
    
    let index = Index::<E>::create(a, b, c, oracle_params, rng).unwrap();

    // We have the Index. Let's choose an example satisfying witness for Jubjub y^2-x^2=1+d*y^2*x^2
    let x = <E::Fr as std::str::FromStr>::from_str("47847771272602875687997868466650874407263908316223685522183521003714784842376").unwrap();
    let y = <E::Fr as std::str::FromStr>::from_str("14866155869058627094034298869399931786023896160785945564212907054495032619276").unwrap();

    // check whether the point is on the curve
    let xx = x.square();
    let yy = y.square();
    let yy_xx_1 = yy-&xx-&one;
    let dxx = d*&xx;
    let dxxyy = dxx*&yy;
    assert_eq!(yy_xx_1, dxxyy);

    /*
    the point is on the curve, let's compute the witness and verify the circuit satisfiability
        Wire labels
        [1, x, y, xx, yy]
    */
    let mut witness = Witness::<E::Fr>::create(8, 8);
    witness.0[0] = one;
    witness.0[1] = x;
    witness.0[2] = y;
    witness.0[3] = xx;
    witness.0[4] = yy;

    // verify the circuit satisfiability by the computed witness
    assert_eq!(index.verify(&witness), true);

    // The computation circuit is satisfied by the witness
    // Now let's chose invalid witness by changing just one digit
    
    let x = <E::Fr as std::str::FromStr>::from_str("57847771272602875687997868466650874407263908316223685522183521003714784842376").unwrap();
    let y = <E::Fr as std::str::FromStr>::from_str("14866155869058627094034298869399931786023896160785945564212907054495032619276").unwrap();

    // check whether the point is on the curve
    let xx = x.square();
    let yy = y.square();
    let yy_xx_1 = yy-&xx-&one;
    let dxx = d*&xx;
    let dxxyy = dxx*&yy;
    assert_ne!(yy_xx_1, dxxyy);

    /*
    the point is on the curve, let's compute the witness and verify the circuit satisfiability
        Wire labels
        [1, x, y, xx, yy]
    */
    let mut witness = Witness::<E::Fr>::create(8, 8);
    witness.0[0] = one;
    witness.0[1] = x;
    witness.0[2] = y;
    witness.0[3] = xx;
    witness.0[4] = yy;

    // verify the circuit satisfiability by the computed witness
    assert_eq!(index.verify(&witness), false);

    // The computation circuit is not satisfied by the witness
}
