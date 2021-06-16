/*********************************************************************************************************

This source file tests constraints for the following computations:

1. Weierstrass curve group addition of non-special pairs of points
   via generic Plonk constraints

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

2. Weierstrass curve group addition of non-special pairs of points
    via custom Plonk constraints

3. Weierstrass curve group doubling of non-special pairs of points
   via generic Plonk constraints

4. Weierstrass curve group doubling of non-special pairs of points
    via custom Plonk constraints

5. Poseidon hash function permutation via custom Plonk constraints

6. Packing via custom Plonk constraints

7. short Weierstrass curve variable base scalar multiplication via custom Plonk constraints without packing

8. short Weierstrass curve variable base scalar multiplication via custom Plonk constraints with packing

9. short Weierstrass curve group endomorphism optimised variable base
   scalar multiplication via custom Plonk constraints

**********************************************************************************************************/

use ark_ff::{BigInteger, Field, One, PrimeField, SquareRootField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D, UVPolynomial,
};
use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRSSpec, SRS},
};
use groupmap::GroupMap;
use mina_curves::pasta::{
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
    Fp,
};
use oracle::{
    poseidon::{
        ArithmeticSponge, ArithmeticSpongeParams, PlonkSpongeConstants5W, Sponge, SpongeConstants,
    },
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use plonk_5_wires_circuits::{constraints::ConstraintSystem, gate::CircuitGate, wires::Wire};
use plonk_5_wires_protocol_dlog::{index::Index, prover::ProverProof};
use rand_core::OsRng;
use std::time::Instant;
use std::{io, io::Write};

const MAX_SIZE: usize = 2048; // max size of poly chunks
const N: usize = 2048; // Plonk domain size
const PUBLIC: usize = 6;

#[test]
fn turbo_plonk() {
    let z = Fp::zero();
    let p = Fp::one();
    let n = -Fp::one();

    // circuit gates

    let mut gates = vec![
        // public input constraints

        /*
            | x1 | .. | .. | .. | .. |
            --------------------------
            | x2 | .. | .. | .. | .. |
            --------------------------
            | x3 | .. | .. | .. | .. |
            --------------------------
            | y1 | .. | .. | .. | .. |
            --------------------------
            | y2 | .. | .. | .. | .. |
            --------------------------
            | y3 | .. | .. | .. | .. |
        */
        CircuitGate::<Fp>::create_generic(
            0,
            [
                Wire { col: 0, row: 6 },
                Wire { col: 1, row: 0 },
                Wire { col: 2, row: 0 },
                Wire { col: 3, row: 0 },
                Wire { col: 4, row: 0 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            1,
            [
                Wire { col: 1, row: 6 },
                Wire { col: 1, row: 1 },
                Wire { col: 2, row: 1 },
                Wire { col: 3, row: 1 },
                Wire { col: 4, row: 1 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            2,
            [
                Wire { col: 4, row: 8 },
                Wire { col: 1, row: 2 },
                Wire { col: 2, row: 2 },
                Wire { col: 3, row: 2 },
                Wire { col: 4, row: 2 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            3,
            [
                Wire { col: 2, row: 7 },
                Wire { col: 1, row: 3 },
                Wire { col: 2, row: 3 },
                Wire { col: 3, row: 3 },
                Wire { col: 4, row: 3 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            4,
            [
                Wire { col: 3, row: 7 },
                Wire { col: 1, row: 4 },
                Wire { col: 2, row: 4 },
                Wire { col: 3, row: 4 },
                Wire { col: 4, row: 4 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            5,
            [
                Wire { col: 3, row: 10 },
                Wire { col: 1, row: 5 },
                Wire { col: 2, row: 5 },
                Wire { col: 3, row: 5 },
                Wire { col: 4, row: 5 },
            ],
            [p, z, z, z, z],
            z,
            z,
        ),
        /* generic constraint gates for Weierstrass curve group addition

            (x2 - x1) * s = y2 - y1
            s * s = x1 + x2 + x3
            (x1 - x3) * s = y3 + y1

            x1 - x2 + a1
            a1 * s + y1 - y2
            s * s - x1 - x2 - x3
            x1 - x3 - a2
            a2 * s - y1 - y3

            | x1 | x2 | a1 | .. | .. |
            --------------------------
            | a1 | s  | y1 | y2 | .. |
            --------------------------
            | s  | s  | x1 | x2 | x3 |
            --------------------------
            | x1 | x3 | a2 | .. | .. |
            --------------------------
            | a2 | s  | y1 | y3 | .. |
        */
        CircuitGate::<Fp>::create_generic(
            6,
            [
                Wire { col: 2, row: 8 },
                Wire { col: 3, row: 8 },
                Wire { col: 0, row: 7 },
                Wire { col: 3, row: 6 },
                Wire { col: 4, row: 6 },
            ],
            [p, n, p, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            7,
            [
                Wire { col: 2, row: 6 },
                Wire { col: 0, row: 8 },
                Wire { col: 2, row: 10 },
                Wire { col: 3, row: 11 },
                Wire { col: 4, row: 7 },
            ],
            [z, z, p, n, z],
            p,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            8,
            [
                Wire { col: 1, row: 8 },
                Wire { col: 1, row: 10 },
                Wire { col: 0, row: 9 },
                Wire { col: 2, row: 11 },
                Wire { col: 1, row: 9 },
            ],
            [z, z, p, p, p],
            n,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            9,
            [
                Wire { col: 0, row: 11 },
                Wire { col: 0, row: 12 },
                Wire { col: 0, row: 10 },
                Wire { col: 3, row: 9 },
                Wire { col: 4, row: 9 },
            ],
            [p, n, n, z, z],
            z,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            10,
            [
                Wire { col: 2, row: 9 },
                Wire { col: 1, row: 7 },
                Wire { col: 1, row: 11 },
                Wire { col: 1, row: 12 },
                Wire { col: 4, row: 10 },
            ],
            [z, z, p, p, z],
            n,
            z,
        ),
    ];

    /* custom constraint gates for Weierstrass curve group addition
        | x1 | y1 | x2 | y2 | r  |
        --------------------------
        | x3 | y3 | .. | .. | .. |
    */

    let mut add = CircuitGate::<Fp>::create_add(
        11,
        &[
            [
                Wire { col: 0, row: 13 },
                Wire { col: 0, row: 14 },
                Wire { col: 0, row: 1 },
                Wire { col: 0, row: 4 },
                Wire { col: 4, row: 11 },
            ],
            [
                Wire { col: 0, row: 2 },
                Wire { col: 0, row: 5 },
                Wire { col: 2, row: 12 },
                Wire { col: 3, row: 12 },
                Wire { col: 4, row: 12 },
            ],
        ],
    );
    gates.append(&mut add);

    /* generic constraint gates for Weierstrass curve group doubling

            2 * s * y1 = 3 * x1^2
            x2 = s^2 – 2*x1
            y2 = -y1 - s * (x2 – x1)

            x1 * x1 - x12
            2 * y1 * s - 3 * x12
            s * s - 2*x1 – x2
            s * x21 + y1 + y2
            x2 – x1 - x21

            | x1 | x1 |x12 | .. | .. |
            --------------------------
            | y1 | s  |x12 | .. | .. |
            --------------------------
            | s  | s  | x1 | x2 | .. |
            --------------------------
            | s  |x21 | y1 | y2 | .. |
            --------------------------
            | x2 | x1 |x21 | .. | .. |
    */

    let mut double = vec![
        CircuitGate::<Fp>::create_generic(
            13,
            [
                Wire { col: 1, row: 13 },
                Wire { col: 2, row: 15 },
                Wire { col: 2, row: 14 },
                Wire { col: 3, row: 13 },
                Wire { col: 4, row: 13 },
            ],
            [z, z, n, z, z],
            p,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            14,
            [
                Wire { col: 2, row: 16 },
                Wire { col: 0, row: 15 },
                Wire { col: 2, row: 13 },
                Wire { col: 3, row: 14 },
                Wire { col: 4, row: 14 },
            ],
            [z, z, (n.double() + &n), z, z],
            p.double(),
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            15,
            [
                Wire { col: 1, row: 15 },
                Wire { col: 0, row: 16 },
                Wire { col: 1, row: 17 },
                Wire { col: 0, row: 17 },
                Wire { col: 4, row: 15 },
            ],
            [z, z, n.double(), n, z],
            p,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            16,
            [
                Wire { col: 1, row: 14 },
                Wire { col: 2, row: 17 },
                Wire { col: 1, row: 18 },
                Wire { col: 3, row: 18 },
                Wire { col: 4, row: 16 },
            ],
            [z, z, p, p, z],
            p,
            z,
        ),
        CircuitGate::<Fp>::create_generic(
            17,
            [
                Wire { col: 2, row: 18 },
                Wire { col: 0, row: 18 },
                Wire { col: 1, row: 16 },
                Wire { col: 3, row: 17 },
                Wire { col: 4, row: 17 },
            ],
            [p, n, n, z, z],
            z,
            z,
        ),
    ];
    gates.append(&mut double);

    /* custom constraint gates for Weierstrass curve group doubling
        | x1 | y1 | x2 | y2 | r  |
    */

    let double = CircuitGate::<Fp>::create_double(
        18,
        [
            Wire { col: 0, row: 0 },
            Wire { col: 0, row: 3 },
            Wire { col: 3, row: 15 },
            Wire { col: 3, row: 16 },
            Wire { col: 4, row: 18 },
        ],
    );
    gates.push(double);

    // custom constraints for Poseidon hash function permutation

    let c = &oracle::pasta::fp5::params().round_constants;
    for i in 0..PlonkSpongeConstants5W::ROUNDS_FULL {
        gates.push(CircuitGate::<Fp>::create_poseidon(
            i + 19,
            [
                Wire {
                    col: 0,
                    row: i + 19,
                },
                Wire {
                    col: 1,
                    row: i + 19,
                },
                Wire {
                    col: 2,
                    row: i + 19,
                },
                Wire {
                    col: 3,
                    row: i + 19,
                },
                Wire {
                    col: 4,
                    row: i + 19,
                },
            ],
            c[i].clone(),
        ));
    }
    let mut i = PlonkSpongeConstants5W::ROUNDS_FULL + 19;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 0, row: i },
            Wire { col: 1, row: i },
            Wire { col: 2, row: i },
            Wire { col: 3, row: i },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;

    // custom constraints for packing

    for _ in 0..64 {
        gates.push(CircuitGate::<Fp>::create_pack(
            i,
            [
                Wire { col: 0, row: i },
                Wire { col: 1, row: i },
                Wire { col: 2, row: i },
                Wire { col: 3, row: i },
                Wire { col: 4, row: i },
            ],
        ));
        i += 1;
    }
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 0, row: i },
            Wire { col: 1, row: i },
            Wire { col: 2, row: i },
            Wire { col: 3, row: i },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;

    // custom constraint gates for short Weierstrass curve variable base scalar multiplication without packing

    gates.push(CircuitGate::<Fp>::create_vbmul(
        i,
        [
            Wire { col: 0, row: i + 2 },
            Wire { col: 1, row: i + 2 },
            Wire {
                col: 2,
                row: i + 512,
            },
            Wire { col: 3, row: i },
            Wire {
                col: 3,
                row: i + 512,
            },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 2, row: i + 2 },
            Wire { col: 3, row: i + 2 },
            Wire {
                col: 2,
                row: i + 512,
            },
            Wire {
                col: 3,
                row: i + 512,
            },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    for j in 0..254 {
        gates.push(CircuitGate::<Fp>::create_vbmul(
            i + 2 * j,
            [
                Wire {
                    col: 0,
                    row: i + 2 * j + 2,
                },
                Wire {
                    col: 1,
                    row: i + 2 * j + 2,
                },
                Wire {
                    col: 2,
                    row: i + 2 * j + 512,
                },
                Wire {
                    col: 3,
                    row: i + 2 * j,
                },
                Wire {
                    col: 3,
                    row: i + 512 + 2 * j,
                },
            ],
        ));
        gates.push(CircuitGate::<Fp>::zero(
            i + 1 + 2 * j,
            [
                Wire {
                    col: 2,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 3,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 0,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 1,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 4,
                    row: i + 1 + 2 * j,
                },
            ],
        ));
    }
    i += 508;
    gates.push(CircuitGate::<Fp>::create_vbmul(
        i,
        [
            Wire { col: 0, row: i + 2 },
            Wire { col: 1, row: i + 2 },
            Wire {
                col: 2,
                row: i + 512,
            },
            Wire { col: 3, row: i },
            Wire {
                col: 3,
                row: i + 512,
            },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire {
                col: 0,
                row: i + 512,
            },
            Wire {
                col: 1,
                row: i + 512,
            },
            Wire { col: 0, row: i - 2 },
            Wire { col: 1, row: i - 2 },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;

    // custom constraint gates for short Weierstrass curve variable base scalar multiplication with packing

    gates.push(CircuitGate::<Fp>::create_vbmul2(
        i,
        [
            Wire { col: 0, row: i + 2 },
            Wire { col: 1, row: i + 2 },
            Wire {
                col: 2,
                row: i - 512,
            },
            Wire {
                col: 4,
                row: i - 512,
            },
            Wire { col: 4, row: i + 3 },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 2, row: i + 2 },
            Wire { col: 3, row: i + 2 },
            Wire {
                col: 2,
                row: i - 512,
            },
            Wire {
                col: 3,
                row: i - 512,
            },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    for j in 0..254 {
        gates.push(CircuitGate::<Fp>::create_vbmul2(
            i + 2 * j,
            [
                Wire {
                    col: 0,
                    row: i + 2 * j + 2,
                },
                Wire {
                    col: 1,
                    row: i + 2 * j + 2,
                },
                Wire {
                    col: 2,
                    row: i + 2 * j - 512,
                },
                Wire {
                    col: 4,
                    row: i + 2 * j - 512,
                },
                Wire {
                    col: 4,
                    row: i + 2 * j + 3,
                },
            ],
        ));
        gates.push(CircuitGate::<Fp>::zero(
            i + 1 + 2 * j,
            [
                Wire {
                    col: 2,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 3,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 0,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 1,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 4,
                    row: i + 1 + 2 * j - 3,
                },
            ],
        ));
    }
    i += 508;
    gates.push(CircuitGate::<Fp>::create_vbmul2(
        i,
        [
            Wire {
                col: 0,
                row: i - 1022,
            },
            Wire {
                col: 1,
                row: i - 1022,
            },
            Wire {
                col: 2,
                row: i - 512,
            },
            Wire {
                col: 4,
                row: i - 512,
            },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire {
                col: 0,
                row: i - 512,
            },
            Wire {
                col: 1,
                row: i - 512,
            },
            Wire { col: 0, row: i - 2 },
            Wire { col: 1, row: i - 2 },
            Wire { col: 4, row: i - 3 },
        ],
    ));
    i += 1;

    // custom constraint gates for short Weierstrass curve variable base endoscalar multiplication

    gates.push(CircuitGate::<Fp>::create_endomul(
        i,
        [
            Wire { col: 0, row: i + 2 },
            Wire { col: 1, row: i + 2 },
            Wire { col: 2, row: i },
            Wire { col: 3, row: i },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 2, row: i + 2 },
            Wire { col: 3, row: i + 2 },
            Wire { col: 2, row: i },
            Wire { col: 3, row: i },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    for j in 0..126 {
        gates.push(CircuitGate::<Fp>::create_endomul(
            i + 2 * j,
            [
                Wire {
                    col: 0,
                    row: i + 2 + 2 * j,
                },
                Wire {
                    col: 1,
                    row: i + 2 + 2 * j,
                },
                Wire {
                    col: 2,
                    row: i + 2 * j,
                },
                Wire {
                    col: 3,
                    row: i + 2 * j,
                },
                Wire {
                    col: 4,
                    row: i + 2 * j,
                },
            ],
        ));
        gates.push(CircuitGate::<Fp>::zero(
            i + 1 + 2 * j,
            [
                Wire {
                    col: 2,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 3,
                    row: i + 3 + 2 * j,
                },
                Wire {
                    col: 0,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 1,
                    row: i - 1 + 2 * j,
                },
                Wire {
                    col: 4,
                    row: i + 1 + 2 * j,
                },
            ],
        ));
    }
    i += 252;
    gates.push(CircuitGate::<Fp>::create_endomul(
        i,
        [
            Wire {
                col: 0,
                row: i - 254,
            },
            Wire {
                col: 1,
                row: i - 254,
            },
            Wire { col: 2, row: i },
            Wire { col: 3, row: i },
            Wire { col: 4, row: i },
        ],
    ));
    i += 1;
    gates.push(CircuitGate::<Fp>::zero(
        i,
        [
            Wire { col: 0, row: i },
            Wire { col: 1, row: i },
            Wire { col: 0, row: i - 2 },
            Wire { col: 1, row: i - 2 },
            Wire { col: 4, row: i },
        ],
    ));

    let srs = SRS::create(MAX_SIZE);

    let (endo_q, _endo_r) = endos::<Other>();
    let index = Index::<Affine>::create(
        ConstraintSystem::<Fp>::create(
            gates,
            oracle::pasta::fp5::params() as ArithmeticSpongeParams<Fp>,
            PUBLIC,
        )
        .unwrap(),
        oracle::pasta::fq5::params(),
        endo_q,
        SRSSpec::Use(&srs),
    );

    positive(&index);
    negative(&index);
}

fn positive(index: &Index<Affine>) {
    let rng = &mut OsRng;
    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let lgr_comms: Vec<_> = (0..PUBLIC)
        .map(|i| {
            let mut v = vec![Fp::zero(); i + 1];
            v[i] = Fp::one();

            let p =
                Evaluations::<Fp, D<Fp>>::from_vec_and_domain(v, index.cs.domain.d1).interpolate();
            index.srs.get_ref().commit_non_hiding(&p, None)
        })
        .collect();
    let mut w = || -> Fp { Fp::rand(rng) };

    println!("{}", "Prover 10 zk-proofs computation".green());
    let verifier_index = index.verifier_index();
    let mut start = Instant::now();

    for test in 0..10 {
        let (x1, y1) = sample_point::<Fp>();
        let (mut x2, mut y2) = sample_point::<Fp>();
        while x1 == x2 {
            let (x, y) = sample_point::<Fp>();
            x2 = x;
            y2 = y;
        }
        let (x3, y3) = add_points((x1, y1), (x2, y2));

        let a1 = x2 - &x1;
        let a2 = x1 - &x3;
        let r1 = a1.inverse().unwrap();
        let s1 = (y2 - &y1) * &r1;

        let (x4, y4) = add_points((x1, y1), (x1, y1));
        let x41 = x4 - &x1;
        let x12 = x1.square();
        let s2 = (x12.double() + x12) / &y1.double();
        let r2 = y1.inverse().unwrap();

        /* public input and EC addition witness for generic constraints

                | x1 | .. | .. | .. | .. |
                --------------------------
                | x2 | .. | .. | .. | .. |
                --------------------------
                | x3 | .. | .. | .. | .. |
                --------------------------
                | y1 | .. | .. | .. | .. |
                --------------------------
                | y2 | .. | .. | .. | .. |
                --------------------------
                | y3 | .. | .. | .. | .. |
                --------------------------
                | x1 | x2 | a1 | .. | .. |
                --------------------------
                | a1 | s1 | y1 | y2 | .. |
                --------------------------
                | s1 | s1 | x1 | x2 | x3 |
                --------------------------
                | x1 | x3 | a2 | .. | .. |
                --------------------------
                | a2 | s1 | y1 | y3 | .. |

            witness for custom gates for Weierstrass curve group addition

                | x1 | y1 | x2 | y2 | r1 |
                --------------------------
                | x3 | y3 | .. | .. | .. |

            witness for generic constraint gates for Weierstrass curve group doubling

                | x1 | x1 |x12 | .. | .. |
                --------------------------
                | y1 | s2 |x12 | .. | .. |
                --------------------------
                | s2 | s2 | x1 | x4 | .. |
                --------------------------
                | s2 |x41 | y1 | y4 | .. |
                --------------------------
                | x4 | x1 |x41 | .. | .. |

            witness for custom constraint gate for Weierstrass curve group doubling

                | x1 | y1 | x4 | y4 | r2 |
        */

        let mut witness = [
            vec![
                x1, x2, x3, y1, y2, y3, x1, a1, s1, x1, a2, x1, x3, x1, y1, s2, s2, x4, x1,
            ],
            vec![
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                x2,
                s1,
                s1,
                x3,
                s1,
                y1,
                y3,
                x1,
                s2,
                s2,
                x41,
                x1,
                y1,
            ],
            vec![
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                a1,
                y1,
                x1,
                a2,
                y1,
                x2,
                w(),
                x12,
                x12,
                x1,
                y1,
                x41,
                x4,
            ],
            vec![
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                y2,
                x2,
                w(),
                y3,
                y2,
                w(),
                w(),
                w(),
                x4,
                y4,
                w(),
                y4,
            ],
            vec![
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                x3,
                w(),
                w(),
                r1,
                w(),
                w(),
                w(),
                w(),
                w(),
                w(),
                r2,
            ],
        ];

        //  witness for Poseidon permutation custom constraints

        let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstants5W>::new(oracle::pasta::fp5::params());
        sponge.state = vec![w(), w(), w(), w(), w()];
        witness
            .iter_mut()
            .zip(sponge.state.iter())
            .for_each(|(w, s)| w.push(*s));

        // ROUNDS_FULL full rounds

        for j in 0..PlonkSpongeConstants5W::ROUNDS_FULL {
            sponge.full_round(j);
            witness
                .iter_mut()
                .zip(sponge.state.iter())
                .for_each(|(w, s)| w.push(*s));
        }

        // witness for packing

        let mut pack = [
            Vec::<Fp>::new(),
            Vec::<Fp>::new(),
            Vec::<Fp>::new(),
            Vec::<Fp>::new(),
            Vec::<Fp>::new(),
        ];

        let scalar = w();
        let bits = scalar
            .into_repr()
            .to_bits()
            .iter()
            .map(|b| match *b {
                true => Fp::one(),
                false => Fp::zero(),
            })
            .collect::<Vec<_>>();
        assert_eq!(bits.len(), 256);

        pack.iter_mut().for_each(|w| w.push(Fp::zero()));
        for k in 0..64 {
            let w0 = bits[4 * k];
            pack[0].push(w0);
            let w1 = bits[4 * k + 1];
            pack[1].push(w1);
            let w2 = bits[4 * k + 2];
            pack[2].push(w2);
            let w3 = bits[4 * k + 3];
            pack[3].push(w3);

            pack[4].push(
                w3 + &w2.double()
                    + &w1.double().double()
                    + &w0.double().double().double()
                    + &pack[4][k].double().double().double().double(),
            );
        }

        assert_eq!(scalar, pack[4][64]);
        witness
            .iter_mut()
            .zip(pack.iter_mut())
            .for_each(|(w, p)| w.append(p));

        // witness for short Weierstrass curve variable base scalar multiplication, no packing

        let (xt, yt) = (x1, y1);
        let (mut xp, mut yp) = add_points(add_points((xt, yt), (xt, yt)), (xt, yt));

        for b in bits.iter() {
            let (xq, yq) = (xt, (b.double() - Fp::one()) * yt);
            let (xs, ys) = add_points(add_points((xq, yq), (xp, yp)), (xp, yp));
            // (xq - xp) * s1 = yq - yp
            let s1 = (yq - &yp) / &(xq - &xp);
            // (xp – xs) * s2 = ys + yp
            let s2 = (ys + &yp) / &(xp - &xs);

            witness[0].push(xt);
            witness[0].push(xs);
            witness[1].push(yt);
            witness[1].push(ys);
            witness[2].push(s1);
            witness[2].push(xp);
            witness[3].push(s2);
            witness[3].push(yp);
            witness[4].push(*b);
            witness[4].push(w());

            xp = xs;
            yp = ys;
        }

        // witness for short Weierstrass curve variable base scalar multiplication, with packing

        let (mut xp, mut yp) = add_points(add_points((xt, yt), (xt, yt)), (xt, yt));
        let mut n2 = Fp::zero();
        let mut n1: Fp;

        for b in bits.iter() {
            let (xq, yq) = (xt, (b.double() - Fp::one()) * yt);
            let (xs, ys) = add_points(add_points((xq, yq), (xp, yp)), (xp, yp));
            // (xq - xp) * s1 = yq - yp
            let s1 = (yq - &yp) / &(xq - &xp);
            n1 = n2.double() + b;

            witness[0].push(xt);
            witness[0].push(xs);
            witness[1].push(yt);
            witness[1].push(ys);
            witness[2].push(s1);
            witness[2].push(xp);
            witness[3].push(*b);
            witness[3].push(yp);
            witness[4].push(n1);
            witness[4].push(n2);

            xp = xs;
            yp = ys;
            n2 = n1;
        }
        assert_eq!(scalar, n2);

        // witness for short Weierstrass curve variable base endoscalar multiplication, no packing

        let (xt, yt) = (x1, y1);
        let (mut xp, mut yp) =
            add_points(add_points((index.cs.endo * &xt, yt), (xt, yt)), (xt, yt));

        for b in bits.chunks_exact(2) {
            let (xq, yq) = (
                (Fp::one() + (index.cs.endo - Fp::one()) * b[0]) * xt,
                (b[1].double() - Fp::one()) * yt,
            );
            let (xs, ys) = add_points(add_points((xp, yp), (xp, yp)), (xq, yq));
            // (xq - xp) * s1 = yq - yp
            let s1 = (yq - &yp) / &(xq - &xp);
            // (xp – xs) * s2 = ys + yp
            let s2 = (ys + &yp) / &(xp - &xs);

            witness[0].push(xt);
            witness[0].push(xs);
            witness[1].push(yt);
            witness[1].push(ys);
            witness[2].push(s1);
            witness[2].push(xp);
            witness[3].push(s2);
            witness[3].push(yp);
            witness[4].push(b[1]);
            witness[4].push(b[0]);

            xp = xs;
            yp = ys;
        }

        witness.iter_mut().for_each(|w| w.resize(N, Fp::zero()));

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&witness), true);

        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals: Vec<_> = (0..k).map(|_| w()).collect();
            let comm = {
                let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(&chals));
                index.srs.get_ref().commit_non_hiding(&b, None)
            };
            (chals, comm)
        };

        // add the proof to the batch
        batch.push(
            ProverProof::create::<
                DefaultFqSponge<VestaParameters, PlonkSpongeConstants5W>,
                DefaultFrSponge<Fp, PlonkSpongeConstants5W>,
            >(&group_map, &witness, &index, vec![prev])
            .unwrap(),
        );

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    // verify one proof serially
    match ProverProof::verify::<
        DefaultFqSponge<VestaParameters, PlonkSpongeConstants5W>,
        DefaultFrSponge<Fp, PlonkSpongeConstants5W>,
    >(&group_map, &vec![(&verifier_index, &lgr_comms, &batch[0])])
    {
        Err(error) => panic!("Failure verifying the prover's proof: {}", error),
        Ok(_) => {}
    }

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    let batch: Vec<_> = batch
        .iter()
        .map(|p| (&verifier_index, &lgr_comms, p))
        .collect();
    match ProverProof::verify::<
        DefaultFqSponge<VestaParameters, PlonkSpongeConstants5W>,
        DefaultFrSponge<Fp, PlonkSpongeConstants5W>,
    >(&group_map, &batch)
    {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
        }
    }
}

fn negative(index: &Index<Affine>) {
    // non-satisfying witness
    let (x1, y1) = sample_point::<Fp>();
    let (x2, y2) = sample_point::<Fp>();
    let (mut x3, y3) = add_points((x1, y1), (x2, y2));
    x3 = x3 - Fp::one();

    let a1 = x2 - &x1;
    let a2 = x1 - &x3;
    let s = (y2 - &y1) / &(x2 - &x1);

    let rng = &mut OsRng;
    let mut w = || -> Fp { Fp::rand(rng) };

    let mut l = vec![x1, x2, x3, y1, y2, y3, x1, a1, s, x1, a2];
    let mut r = vec![w(), w(), w(), w(), w(), w(), x2, s, s, x3, s];
    let mut o = vec![w(), w(), w(), w(), w(), w(), a1, y1, x1, a2, y1];
    let mut a = vec![w(), w(), w(), w(), w(), w(), w(), y2, x2, w(), y3];
    let mut b = vec![w(), w(), w(), w(), w(), w(), w(), w(), x3, w(), w()];

    l.resize(N, Fp::zero());
    r.resize(N, Fp::zero());
    o.resize(N, Fp::zero());
    a.resize(N, Fp::zero());
    b.resize(N, Fp::zero());

    // verify the circuit negative satisfiability by the computed witness
    assert_eq!(index.cs.verify(&[l, r, o, a, b]), false);
}

fn add_points(a: (Fp, Fp), b: (Fp, Fp)) -> (Fp, Fp) {
    if a == (Fp::zero(), Fp::zero()) {
        b
    } else if b == (Fp::zero(), Fp::zero()) {
        a
    } else if a.0 == b.0 && (a.1 != b.1 || b.1 == Fp::zero()) {
        (Fp::zero(), Fp::zero())
    } else if a.0 == b.0 && a.1 == b.1 {
        let sq = a.0.square();
        let s = (sq.double() + &sq) / &a.1.double();
        let x = s.square() - &a.0.double();
        let y = -a.1 - &(s * &(x - &a.0));
        (x, y)
    } else {
        let s = (a.1 - &b.1) / &(a.0 - &b.0);
        let x = s.square() - &a.0 - &b.0;
        let y = -a.1 - &(s * &(x - &a.0));
        (x, y)
    }
}

fn sample_point<F: PrimeField + SquareRootField>() -> (F, F) {
    let rng = &mut OsRng;
    let x = F::rand(rng);
    let mut y2 = x.square() * x + F::one().double().double() + F::one();
    while y2.legendre().is_qnr() == true {
        let x = F::rand(rng);
        y2 = x.square() * x + F::one().double().double() + F::one();
    }

    (x, y2.sqrt().unwrap())
}
