use std::array;

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateResult, GateType},
        polynomials::keccak::{
            collapse, compose, decompose, expand, reset, shift, witness::extend_keccak_witness,
            KECCAK_COLS, QUARTERS,
        },
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    tests::framework::TestFramework,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use mina_curves::pasta::{Fq, Pallas, PallasParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::{BigUint, RandBigInt};
use o1_utils::{BigUintHelpers, FieldHelpers};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use super::framework::TestRunner;

type SpongeParams = PlonkSpongeConstantsKimchi;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

fn create_test_gates<G: KimchiCurve>(bytelength: usize) -> Vec<CircuitGate<G::ScalarField>>
where
    G::BaseField: PrimeField,
{
    let mut gates = vec![];
    let next_row = CircuitGate::<G::ScalarField>::extend_keccak(&mut gates, bytelength);
    // Adding dummy row to avoid out of bounds in squeeze constraints accessing Next row
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });

    gates
}

fn create_keccak_witness<G: KimchiCurve>(message: BigUint) -> [Vec<G::ScalarField>; KECCAK_COLS]
where
    G::BaseField: PrimeField,
{
    let mut witness: [Vec<G::ScalarField>; KECCAK_COLS] =
        array::from_fn(|_| vec![G::ScalarField::zero(); 0]);
    extend_keccak_witness(&mut witness, message);
    // Adding dummy row to avoid out of bounds in squeeze constraints accessing Next row
    let dummy_row: [Vec<G::ScalarField>; KECCAK_COLS] =
        array::from_fn(|_| vec![G::ScalarField::zero()]);
    for col in 0..KECCAK_COLS {
        witness[col].extend(dummy_row[col].iter());
    }
    witness
}

fn print_witness<F: Field>(witness: &[Vec<F>; KECCAK_COLS], round: usize) {
    fn to_u64<F: Field>(elem: F) -> u64 {
        let mut bytes = FieldHelpers::<F>::to_bytes(&elem);
        bytes.reverse();
        bytes.iter().fold(0, |acc: u64, x| (acc << 8) + *x as u64)
    }
    fn print_line(state: &[u64]) {
        print!("         ");
        for x in 0..5 {
            let quarters = &state[4 * x..4 * (x + 1)];
            let word = compose(&collapse(&reset(&shift(quarters))));
            print!("{:016x} ", word);
        }
        println!();
    }
    fn print_matrix(state: &[u64]) {
        for x in 0..5 {
            print!("         ");
            for y in 0..5 {
                let quarters = &state[4 * (5 * y + x)..4 * (5 * y + x) + 4];
                let word = compose(&collapse(&reset(&shift(quarters))));
                print!("{:016x} ", word);
            }
            println!();
        }
    }

    let row = witness
        .iter()
        .map(|x| to_u64::<F>(x[round]))
        .collect::<Vec<u64>>();
    let next = witness
        .iter()
        .map(|x| to_u64::<F>(x[round + 1]))
        .collect::<Vec<u64>>();

    println!("----------------------------------------");
    println!("ROUND {}", round);
    println!("State A:");
    print_matrix(&row[0..100]);
    println!("State C:");
    print_line(&row[100..120]);
    println!("State D:");
    print_line(&row[320..340]);
    println!("State E:");
    print_matrix(&row[340..440]);
    println!("State B:");
    print_matrix(&row[1440..1540]);

    let mut state_f = row[2340..2344].to_vec();
    let mut tail = next[4..100].to_vec();
    state_f.append(&mut tail);

    println!("State F:");
    print_matrix(&state_f);
    println!("State G:");
    print_matrix(&next[0..100]);
}

const RNG_SEED: [u8; 32] = [
    0, 131, 43, 175, 229, 252, 206, 26, 67, 193, 86, 160, 1, 90, 131, 86, 168, 4, 95, 50, 48, 9,
    192, 13, 250, 215, 172, 130, 24, 164, 162, 221,
];

// Sets up test for a given message and desired input bytelength
fn test_keccak_n<G: KimchiCurve, EFqSponge, EFrSponge>(
    n: usize,
    rng: &mut StdRng,
) -> CircuitGateResult<()>
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<KECCAK_COLS, G::ScalarField>,
{
    let messages = vec![rng.gen_biguint_below(&BigUint::from(2u32).pow(1080)); n];

    let mut gates = vec![];
    let mut witness = array::from_fn(|_| vec![G::ScalarField::zero(); 0]);

    for msg in messages {
        let next_row =
            CircuitGate::<G::ScalarField>::extend_keccak(&mut gates, msg.to_bytes_be().len());
        // Adding dummy row to avoid out of bounds in squeeze constraints accessing Next row
        gates.push(CircuitGate {
            typ: GateType::Zero,
            wires: Wire::for_row(next_row),
            coeffs: vec![],
        });
        let hash_wit: [Vec<<<G as AffineCurve>::Projective as ProjectiveCurve>::ScalarField>;
            KECCAK_COLS] = create_keccak_witness::<G>(msg);
        for col in 0..KECCAK_COLS {
            witness[col].extend(hash_wit[col].iter());
        }
    }

    let runner: TestRunner<2344, G> = TestFramework::<KECCAK_COLS, G>::default()
        .gates(gates.clone())
        .setup();
    let cs = runner.clone().prover_index().cs.clone();
    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result =
            gate.verify_witness::<KECCAK_COLS, G>(row, &witness, &cs, &witness[0][0..cs.public]);
        result?;
    }
    assert_eq!(
        runner
            .clone()
            .witness(witness.clone())
            .prove_and_verify::<EFqSponge, EFrSponge>(),
        Ok(())
    );

    Ok(())
}

// Sets up test for a given message and desired input bytelength
fn test_keccak<G: KimchiCurve, EFqSponge, EFrSponge>(
    message: BigUint,
    full: bool,
) -> (CircuitGateResult<()>, BigUint)
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<KECCAK_COLS, G::ScalarField>,
{
    let bytelength = message.to_bytes_be().len();
    let padded_len = padded_length(bytelength);

    let gates = create_test_gates::<G>(padded_len);
    let witness: [Vec<<<G as AffineCurve>::Projective as ProjectiveCurve>::ScalarField>;
        KECCAK_COLS] = create_keccak_witness::<G>(message);

    for r in 1..=24 {
        print_witness::<G::ScalarField>(&witness, r);
    }

    let mut hash = vec![];
    let hash_row = witness[0].len() - 2; // Hash row is dummy row
    println!();
    println!("----------------------------------------");
    print!("Hash: ");
    for b in 0..32 {
        hash.push(FieldHelpers::to_bytes(&witness[200 + b][hash_row])[0]);
        print!("{:02x}", hash[b]);
    }
    println!();
    println!();
    let hash = BigUint::from_bytes_be(&hash);
    let runner = if full {
        // Create prover index with test framework
        Some(
            TestFramework::<KECCAK_COLS, G>::default()
                .gates(gates.clone())
                .setup(),
        )
    } else {
        None
    };
    let cs = if let Some(runner) = runner.as_ref() {
        runner.clone().prover_index().cs.clone()
    } else {
        ConstraintSystem::create(gates.clone())
            .build::<KECCAK_COLS>()
            .unwrap()
    };
    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result =
            gate.verify_witness::<KECCAK_COLS, G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return (result, hash);
        }
    }

    if let Some(runner) = runner.as_ref() {
        // Perform full test that everything is ok before invalidation
        assert_eq!(
            runner
                .clone()
                .witness(witness.clone())
                .prove_and_verify::<EFqSponge, EFrSponge>(),
            Ok(())
        );
    }

    (Ok(()), hash)
}

#[test]
fn test_bitwise_sparse_representation() {
    assert_eq!(expand(0xFFFF), 0x1111111111111111);

    let word_a: u64 = 0x70d324ac9215fd8e;
    let dense_a = decompose(word_a);
    let real_dense_a = [0xfd8e, 0x9215, 0x24ac, 0x70d3];
    for i in 0..QUARTERS {
        assert_eq!(dense_a[i], real_dense_a[i]);
    }
    assert_eq!(word_a, compose(&dense_a));

    let sparse_a = dense_a.iter().map(|x| expand(*x)).collect::<Vec<u64>>();
    let real_sparse_a: Vec<u64> = vec![
        0x1111110110001110,
        0x1001001000010101,
        0x10010010101100,
        0x111000011010011,
    ];
    for i in 0..QUARTERS {
        assert_eq!(sparse_a[i], real_sparse_a[i]);
    }

    let word_b: u64 = 0x11c76438a7f9e94d;
    let dense_b = decompose(word_b);
    let sparse_b = dense_b.iter().map(|x| expand(*x)).collect::<Vec<u64>>();

    let xor_ab: u64 = word_a ^ word_b;
    assert_eq!(xor_ab, 0x6114409435ec14c3);

    let sparse_xor = decompose(xor_ab)
        .iter()
        .map(|x| expand(*x))
        .collect::<Vec<u64>>();
    let real_sparse_xor = [
        0x1010011000011,
        0x11010111101100,
        0x100000010010100,
        0x110000100010100,
    ];
    for i in 0..QUARTERS {
        assert_eq!(sparse_xor[i], real_sparse_xor[i]);
    }

    let sparse_sum_ab = sparse_a
        .iter()
        .zip(sparse_b.iter())
        .map(|(a, b)| a + b)
        .collect::<Vec<u64>>();
    let shifts_sum_ab = shift(&sparse_sum_ab);
    let reset_sum_ab = reset(&shifts_sum_ab);
    assert_eq!(sparse_xor, reset_sum_ab);

    for i in 0..QUARTERS {
        assert_eq!(
            sparse_sum_ab[i],
            shifts_sum_ab[i]
                + shifts_sum_ab[4 + i] * 2
                + shifts_sum_ab[8 + i] * 4
                + shifts_sum_ab[12 + i] * 8
        )
    }
}

#[test]
// Test hash of message zero with 1 byte
fn test_dummy() {
    stacker::grow(30 * 1024 * 1024, || {
        // guaranteed to have at least 30MB of stack

        let (_, claim1) = test_keccak::<Pallas, PallasBaseSponge, PallasScalarSponge>(
            BigUint::from_bytes_be(&[0x00]),
            true,
        );
        let hash1 =
            BigUint::from_hex("bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");
        assert_eq!(claim1, hash1);
    });
}

#[test]
// Tests a random block of 1080 bits
fn test_random_block() {
    let (_,claim_random) = test_keccak::<Pallas,PallasBaseSponge, PallasScalarSponge >(
        BigUint::from_hex("832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126"),
    false);
    let hash_random =
        BigUint::from_hex("845e9dd4e22b4917a80c5419a0ddb3eebf5f4f7cc6035d827314a18b718f751f");
    assert_eq!(claim_random, hash_random);
}

#[test]
// Test hash of message zero with 1 byte
fn test_blocks() {
    stacker::grow(30 * 1024 * 1024, || {
        let (_,claim_3blocks) = test_keccak::<Pallas,PallasBaseSponge, PallasScalarSponge>(BigUint::from_hex("832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f"), true);
        let hash_3blocks =
            BigUint::from_hex("7e369e1a4362148fca24c67c76f14dbe24b75c73e9b0efdb8c46056c8514287e");
        assert_eq!(claim_3blocks, hash_3blocks);
    });
}

#[test]
// Test hash of message zero with 1 byte
fn test_1000_hashes() {
    stacker::grow(30 * 1024 * 1024, || {
        assert_eq!(
            Ok(()),
            test_keccak_n::<Pallas, PallasBaseSponge, PallasScalarSponge>(
                1000,
                &mut StdRng::from_seed(RNG_SEED),
            )
        );
    });
}
