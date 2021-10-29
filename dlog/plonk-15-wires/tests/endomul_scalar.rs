use ark_ff::{BigInteger, BitIteratorLE, PrimeField, UniformRand};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{
    commitment::CommitmentCurve,
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp as F,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstants15W,
    sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge},
};
use plonk_15_wires_circuits::{
    gate::{CircuitGate, GateType},
    nolookup::constraints::ConstraintSystem,
    polynomials::endomul_scalar,
    wires::*,
};
use plonk_15_wires_protocol_dlog::{index::Index, prover::ProverProof};
use rand::{rngs::StdRng, SeedableRng};
use std::{sync::Arc, time::Instant};

const PUBLIC: usize = 0;

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

#[test]
fn endomul_scalar_test() {
    let fp_sponge_params = oracle::pasta::fp::params();

    let bits_per_row = 2 * 8;
    let num_bits = 128;
    let rows_per_scalar = num_bits / bits_per_row;

    let num_scalars = 100;

    assert_eq!(num_bits % bits_per_row, 0);

    let mut gates = vec![];

    for s in 0..num_scalars {
        for i in 0..rows_per_scalar {
            let row = rows_per_scalar * s + i;
            gates.push(CircuitGate {
                row,
                typ: GateType::EndomulScalar,
                wires: Wire::new(row),
                c: vec![],
            });
        }
    }

    let cs = ConstraintSystem::<F>::create(gates, vec![], fp_sponge_params, PUBLIC).unwrap();
    let _n = cs.domain.d1.size as usize;

    let mut srs = SRS::create(cs.domain.d1.size as usize);
    srs.add_lagrange_basis(cs.domain.d1);

    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let (_, endo_scalar_coeff) = endos::<Affine>();

    let srs = Arc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![]);

    let verifier_index = index.verifier_index();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let lgr_comms = vec![];
    let rng = &mut StdRng::from_seed([0; 32]);

    //let start = Instant::now();
    for i in 0..num_scalars {
        let x = {
            let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_repr())
                .take(num_bits)
                .collect();
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..])).unwrap()
        };

        assert_eq!(
            ScalarChallenge(x).to_field(&endo_scalar_coeff),
            endomul_scalar::witness(
                &mut witness,
                i * rows_per_scalar,
                x,
                endo_scalar_coeff,
                num_bits
            )
        );
    }

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
