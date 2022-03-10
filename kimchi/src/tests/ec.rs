use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        wires::*,
    },
    index::testing::new_index_for_test,
    prover::ProverProof,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp as F,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

const PUBLIC: usize = 0;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

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

    let index = new_index_for_test(gates, PUBLIC);

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![]);

    let verifier_index = index.verifier_index();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let lgr_comms = vec![];
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

    index.cs.verify(&witness, &[]).unwrap();

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index, vec![])
            .unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let batch: Vec<_> = vec![(&verifier_index, &lgr_comms, &proof)];
    let start = Instant::now();
    match ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}
