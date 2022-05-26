use crate::circuits::{
    gate::{CircuitGate, GateType},
    wires::*,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use array_init::array_init;
use mina_curves::pasta::{fp::Fp as F, pallas::Affine as Other};
use rand::{rngs::StdRng, SeedableRng};

use super::framework::TestFramework;

// Tests add and double gates
#[test]
fn ec_test() {
    let num_doubles = 100;
    let num_additions = 100;
    let num_infs = 100;

    let mut gates = vec![];

    for row in 0..(num_doubles + num_additions + num_infs) {
        gates.push(CircuitGate {
            typ: GateType::CompleteAdd,
            wires: Wire::new(row),
            coeffs: vec![],
        });
    }

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![]);

    let rng = &mut StdRng::from_seed([0; 32]);

    let ps = {
        let p = Other::prime_subgroup_generator()
            .into_projective()
            .mul(<Other as AffineCurve>::ScalarField::rand(rng).into_repr())
            .into_affine();
        let mut res = vec![];
        let mut acc = p;
        for _ in 0..num_additions {
            res.push(acc);
            acc = acc + p;
        }
        res
    };

    let qs = {
        let q = Other::prime_subgroup_generator()
            .into_projective()
            .mul(<Other as AffineCurve>::ScalarField::rand(rng).into_repr())
            .into_affine();
        let mut res = vec![];
        let mut acc = q;
        for _ in 0..num_additions {
            res.push(acc);
            acc = acc + q;
        }
        res
    };

    for i in 0..num_doubles {
        let p = ps[i];

        let p2 = p + p;
        let (x1, y1) = (p.x, p.y);
        let x1_squared = x1.square();
        // 2 * s * y1 = 3 * x1^2
        let s = (x1_squared.double() + x1_squared) / y1.double();

        witness[0].push(p.x);
        witness[1].push(p.y);
        witness[2].push(p.x);
        witness[3].push(p.y);
        witness[4].push(p2.x);
        witness[5].push(p2.y);
        witness[6].push(F::zero());
        witness[7].push(F::one());
        witness[8].push(s);
        witness[9].push(F::zero());
        witness[10].push(F::zero());

        witness[11].push(F::zero());
        witness[12].push(F::zero());
        witness[13].push(F::zero());
        witness[14].push(F::zero());
    }

    for i in 0..num_additions {
        let p = ps[i];
        let q = qs[i];

        let pq = p + q;
        let (x1, y1) = (p.x, p.y);
        let (x2, y2) = (q.x, q.y);
        // (x2 - x1) * s = y2 - y1
        let s = (y2 - y1) / (x2 - x1);
        witness[0].push(x1);
        witness[1].push(y1);
        witness[2].push(x2);
        witness[3].push(y2);
        witness[4].push(pq.x);
        witness[5].push(pq.y);
        witness[6].push(F::zero());
        witness[7].push(F::zero());
        witness[8].push(s);
        witness[9].push(F::zero());
        witness[10].push((x2 - x1).inverse().unwrap());

        witness[11].push(F::zero());
        witness[12].push(F::zero());
        witness[13].push(F::zero());
        witness[14].push(F::zero());
    }

    for i in 0..num_infs {
        let p = ps[i];
        let q = -p;

        let p2 = p + p;
        let (x1, y1) = (p.x, p.y);
        let x1_squared = x1.square();
        // 2 * s * y1 = -3 * x1^2
        let s = (x1_squared.double() + x1_squared) / y1.double();
        witness[0].push(p.x);
        witness[1].push(p.y);
        witness[2].push(q.x);
        witness[3].push(q.y);
        witness[4].push(p2.x);
        witness[5].push(p2.y);
        witness[6].push(F::one());
        witness[7].push(F::one());
        witness[8].push(s);
        witness[9].push((q.y - p.y).inverse().unwrap());
        witness[10].push(F::zero());

        witness[11].push(F::zero());
        witness[12].push(F::zero());
        witness[13].push(F::zero());
        witness[14].push(F::zero());
    }

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify();
}
