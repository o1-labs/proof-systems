use std::array;

use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, GateType},
        polynomials::keccak::{
            collapse, compose, pad, reset, shift, witness::extend_keccak_witness, KECCAK_COLS,
        },
        wires::Wire,
    },
    curve::KimchiCurve,
};
use ark_ff::{Field, PrimeField, Zero};
use mina_curves::pasta::Pallas;
use num_bigint::BigUint;
use o1_utils::{BigUintHelpers, FieldHelpers};

fn create_test_constraint_system<G: KimchiCurve>(
    bytelength: usize,
) -> ConstraintSystem<G::ScalarField>
where
    G::BaseField: PrimeField,
{
    let mut gates = vec![];
    let next_row = CircuitGate::extend_keccak(&mut gates, bytelength);
    // Adding dummy row to avoid out of bounds in squeeze constraints accessing Next row
    gates.push(CircuitGate {
        typ: GateType::Zero,
        wires: Wire::for_row(next_row),
        coeffs: vec![],
    });

    ConstraintSystem::create(gates)
        .build::<KECCAK_COLS>()
        .unwrap()
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

fn eprint_witness<F: Field>(witness: &[Vec<F>; KECCAK_COLS], round: usize) {
    fn to_u64<F: Field>(elem: F) -> u64 {
        let mut bytes = FieldHelpers::<F>::to_bytes(&elem);
        bytes.reverse();
        bytes.iter().fold(0, |acc: u64, x| (acc << 8) + *x as u64)
    }
    fn eprint_line(state: &[u64]) {
        eprint!("         ");
        for x in 0..5 {
            let quarters = &state[4 * x..4 * (x + 1)];
            let word = compose(&collapse(&reset(&shift(quarters))));
            eprint!("{:016x} ", word);
        }
        eprintln!();
    }
    fn eprint_matrix(state: &[u64]) {
        for x in 0..5 {
            eprint!("         ");
            for y in 0..5 {
                let quarters = &state[4 * (5 * y + x)..4 * (5 * y + x) + 4];
                let word = compose(&collapse(&reset(&shift(quarters))));
                eprint!("{:016x} ", word);
            }
            eprintln!();
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

    eprintln!("----------------------------------------");
    eprintln!("ROUND {}", round);
    eprintln!("State A:");
    eprint_matrix(&row[0..100]);
    eprintln!("State C:");
    eprint_line(&row[100..120]);
    eprintln!("State D:");
    eprint_line(&row[320..340]);
    eprintln!("State E:");
    eprint_matrix(&row[340..440]);
    eprintln!("State B:");
    eprint_matrix(&row[1440..1540]);

    let mut state_f = row[2340..2344].to_vec();
    let mut tail = next[4..100].to_vec();
    state_f.append(&mut tail);

    eprintln!("State F:");
    eprint_matrix(&state_f);
    eprintln!("State G:");
    eprint_matrix(&next[0..100]);
}

// Sets up test for a given message and desired input bytelength
fn setup_keccak_test<G: KimchiCurve>(message: BigUint) -> BigUint
where
    G::BaseField: PrimeField,
{
    let bytelength = message.to_bytes_be().len();
    let padded_len = {
        let mut sized = message.to_bytes_be();
        sized.resize(bytelength - sized.len(), 0);
        pad(&sized).len()
    };
    let _index = create_test_constraint_system::<G>(padded_len);
    let witness = create_keccak_witness::<G>(message);

    for r in 1..=24 {
        eprint_witness::<G::ScalarField>(&witness, r);
    }

    let mut hash = vec![];
    let hash_row = witness[0].len() - 2; // Hash row is dummy row
    eprintln!();
    eprintln!("----------------------------------------");
    eprint!("Hash: ");
    for b in 0..32 {
        hash.push(FieldHelpers::to_bytes(&witness[200 + b][hash_row])[0]);
        eprint!("{:02x}", hash[b]);
    }
    eprintln!();
    eprintln!();

    BigUint::from_bytes_be(&hash)
}

#[test]
// Tests a random block of 1080 bits
fn test_random_block() {
    let expected_random = setup_keccak_test::<Pallas>(
        BigUint::from_hex("832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126"),
    );
    let hash_random =
        BigUint::from_hex("845e9dd4e22b4917a80c5419a0ddb3eebf5f4f7cc6035d827314a18b718f751f");
    assert_eq!(expected_random, hash_random);
}

#[test]
// Test hash of message zero with 1 byte input length
fn test_zero() {
    let expected1 = setup_keccak_test::<Pallas>(BigUint::from_bytes_be(&[0x00]));
    let hash1 =
        BigUint::from_hex("bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");
    assert_eq!(expected1, hash1);
}

#[test]
// Test hash of message using 3 blocks
fn test_blocks() {
    let expected_3blocks = setup_keccak_test::<Pallas>(BigUint::from_hex("832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f423423a214325d13523aadb21414124aaadf32523126832588523900cca2ea9b8c0395d295aa39f9a9285a982b71cc8475067a8175f38f235a2234abc982a2dfaaddff2895a28598021895206a733a22bccd21f124df1413858a8f9a1134df285a888b099a8c2235eecdf2345f3afd32f3ae323526689172850672938104892357aad32523523f"));
    let hash_3blocks =
        BigUint::from_hex("7e369e1a4362148fca24c67c76f14dbe24b75c73e9b0efdb8c46056c8514287e");
    assert_eq!(expected_3blocks, hash_3blocks);
}
