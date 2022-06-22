use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        lookup::tables::{LookupTable, XOR_TABLE_ID},
        polynomials::chacha,
        wires::{Wire, COLUMNS},
    },
    proof::ProverProof,
    prover_index::testing::new_index_for_test,
    verifier::verify,
};
use ark_ff::Zero;
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::time::Instant;

use o1_utils::math;

use super::framework::TestFramework;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const PUBLIC: usize = 0;

#[test]
fn chacha_prover() {
    let num_chachas = 8;
    let rows_per_chacha = 20 * 4 * 10;
    let n_lower_bound = rows_per_chacha * num_chachas;
    let max_size = 1 << math::ceil_log2(n_lower_bound);
    println!("{} {}", n_lower_bound, max_size);

    let s0: Vec<u32> = vec![
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];
    let expected_result: Vec<u32> = vec![
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc,
        0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de,
        0x9e83d0cb, 0x4e3c50a2,
    ];
    assert_eq!(expected_result, chacha::testing::chacha20(s0.clone()));

    // circuit gates
    let mut gates = vec![];
    for _ in 0..num_chachas {
        gates.extend(chacha::testing::chacha20_gates())
    }
    let gates: Vec<CircuitGate<Fp>> = gates
        .into_iter()
        .enumerate()
        .map(|(i, typ)| CircuitGate {
            typ,
            coeffs: vec![],
            wires: Wire::new(i),
        })
        .collect();

    // create the index
    let index = new_index_for_test(gates, PUBLIC);

    let mut rows = vec![];
    for _ in 0..num_chachas {
        rows.extend(chacha::testing::chacha20_rows::<Fp>(s0.clone()))
    }
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![]);
    for r in rows.into_iter() {
        for (col, c) in r.into_iter().enumerate() {
            witness[col].push(c);
        }
    }

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index).unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let start = Instant::now();
    let verifier_index = index.verifier_index();
    println!("{}{:?}", "Verifier index time: ".yellow(), start.elapsed());

    let start = Instant::now();
    match verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}

fn chacha_setup_bad_lookup(table_id: i32) {
    // circuit gates: one 'real' ChaCha0 and one 'fake' one.
    let gates = vec![
        GateType::ChaCha0,
        GateType::Zero,
        GateType::ChaCha0,
        GateType::Zero,
    ];
    let gates: Vec<CircuitGate<Fp>> = gates
        .into_iter()
        .enumerate()
        .map(|(i, typ)| CircuitGate {
            typ,
            coeffs: vec![],
            wires: Wire::new(i),
        })
        // Pad with generic gates to get a sufficiently-large domain.
        .chain((4..513).map(|i| CircuitGate {
            typ: GateType::Generic,
            coeffs: vec![Fp::zero(); 10],
            wires: Wire::new(i),
        }))
        .collect();

    let mut rows = vec![];

    let s: Vec<u32> = vec![
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];

    let mut fakes = vec![vec![]; 3];

    // Push the witnesses for a gate. When `fake` is true, the XOR operation is faked to return 0.
    // This has been shamelessly copied from the chacha module and vandalised.
    let mut push_rows = |fake: bool| {
        let k = 16;
        let x = 0;
        let y = 1;
        let z = 2;
        let f = |t: u32| Fp::from(t);
        let nyb = |t: u32, i: usize| f((t >> (4 * i)) & 0b1111);

        let top_bit = (((s[x] as u64) + (s[z] as u64)) >> 32) as u32;
        let xprime = u32::wrapping_add(s[x], s[z]);
        let y_xor_xprime = if fake {
            for nybble in 0..8 {
                fakes[0].push(nyb(0, nybble));
                fakes[1].push(nyb(xprime, nybble));
                fakes[2].push(nyb(s[y], nybble));
            }
            0
        } else {
            s[y] ^ xprime
        };
        let yprime = y_xor_xprime.rotate_left(k);

        rows.push(vec![
            f(s[x]),
            f(s[y]),
            f(s[z]),
            nyb(y_xor_xprime, 0),
            nyb(y_xor_xprime, 1),
            nyb(y_xor_xprime, 2),
            nyb(y_xor_xprime, 3),
            nyb(xprime, 0),
            nyb(xprime, 1),
            nyb(xprime, 2),
            nyb(xprime, 3),
            nyb(s[y], 0),
            nyb(s[y], 1),
            nyb(s[y], 2),
            nyb(s[y], 3),
        ]);
        rows.push(vec![
            f(xprime),
            f(yprime),
            f(top_bit),
            nyb(y_xor_xprime, 4),
            nyb(y_xor_xprime, 5),
            nyb(y_xor_xprime, 6),
            nyb(y_xor_xprime, 7),
            nyb(xprime, 4),
            nyb(xprime, 5),
            nyb(xprime, 6),
            nyb(xprime, 7),
            nyb(s[y], 4),
            nyb(s[y], 5),
            nyb(s[y], 6),
            nyb(s[y], 7),
        ]);
    };

    // One real witness..
    push_rows(false);
    // .. and one fake witness.
    push_rows(true);

    let lookup_tables = vec![
        LookupTable {
            id: 0,
            data: vec![vec![Fp::from(0); 10]],
        },
        LookupTable {
            id: table_id,
            data: fakes,
        },
    ];

    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![]);
    for r in rows.into_iter() {
        for (col, c) in r.into_iter().enumerate() {
            witness[col].push(c);
        }
    }

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(lookup_tables)
        .setup()
        .prove_and_verify();
}

// Test lookup domain separation: if a different table ID is used, we shouldn't be able to use a
// value from that table.
#[test]
#[should_panic]
fn chacha_prover_fake_lookup_in_different_table_fails() {
    chacha_setup_bad_lookup(XOR_TABLE_ID + 1)
}

// Test lookup domain collisions: if the same table ID is used, we should be able to inject and use
// a value when it wasn't previously in the table.
#[test]
fn chacha_prover_fake_lookup_in_same_table() {
    chacha_setup_bad_lookup(XOR_TABLE_ID)
}
