use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        polynomials::endomul_scalar,
        wires::*,
    },
    index::testing::new_index_for_test,
    prover::ProverProof,
    verifier::batch_verify,
};
use ark_ff::{BigInteger, BitIteratorLE, PrimeField, UniformRand};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{commitment::CommitmentCurve, srs::endos};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp as F,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge},
};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

const PUBLIC: usize = 0;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

#[test]
fn endomul_scalar_test() {
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
                typ: GateType::EndoMulScalar,
                wires: Wire::new(row),
                coeffs: vec![],
            });
        }
    }

    let index = new_index_for_test(gates, PUBLIC);
    let (_, endo_scalar_coeff) = endos::<Affine>();

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![]);

    let verifier_index = index.verifier_index();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let rng = &mut StdRng::from_seed([0; 32]);

    //let start = Instant::now();
    for _ in 0..num_scalars {
        let x = {
            let bits_lsb: Vec<_> = BitIteratorLE::new(F::rand(rng).into_repr())
                .take(num_bits)
                .collect();
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..])).unwrap()
        };

        assert_eq!(
            ScalarChallenge(x).to_field(&endo_scalar_coeff),
            endomul_scalar::gen_witness(&mut witness, x, endo_scalar_coeff, num_bits)
        );
    }

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index, vec![])
            .unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let batch: Vec<_> = vec![(&verifier_index, &proof)];
    let start = Instant::now();
    match batch_verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}
