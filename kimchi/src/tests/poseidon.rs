use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials,
        polynomials::poseidon::{ROUNDS_PER_ROW, SPONGE_WIDTH},
        wires::{Wire, COLUMNS},
    },
    curve::KimchiCurve,
    proof::ProverProof,
    prover_index::testing::new_index_for_test,
    tests::framework::TestFramework,
    verifier::verify,
};
use ark_ff::Zero;
use core::array;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof};
use rand::rngs::OsRng;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;

const NUM_POS: usize = 1; // 1360; // number of Poseidon hashes in the circuit
const ROUNDS_PER_HASH: usize = SpongeParams::PERM_ROUNDS_FULL;
const POS_ROWS_PER_HASH: usize = ROUNDS_PER_HASH / ROUNDS_PER_ROW;
const N_LOWER_BOUND: usize = (POS_ROWS_PER_HASH + 1) * NUM_POS; // Plonk domain size

#[test]
fn test_poseidon() {
    let max_size = 1 << math::ceil_log2(N_LOWER_BOUND);
    println!("max_size = {max_size}");
    println!("rounds per hash = {ROUNDS_PER_HASH}");
    println!("rounds per row = {ROUNDS_PER_ROW}");
    println!(" number of rows for poseidon ={POS_ROWS_PER_HASH}");
    assert_eq!(ROUNDS_PER_HASH % ROUNDS_PER_ROW, 0);

    //let round_constants = mina_poseidon::pasta::fp_kimchi::params().round_constants;
    let round_constants = Vesta::sponge_params().round_constants;

    // we keep track of an absolute row, and relative row within a gadget
    let mut abs_row = 0;

    // circuit gates
    let mut gates: Vec<CircuitGate<Fp>> = Vec::with_capacity(max_size);

    // custom constraints for Poseidon hash function permutation
    // ROUNDS_FULL full rounds constraint gates
    for _ in 0..NUM_POS {
        let first_wire = Wire::for_row(abs_row);
        let last_row = abs_row + POS_ROWS_PER_HASH;
        let last_wire = Wire::for_row(last_row);
        let (poseidon, row) = CircuitGate::<Fp>::create_poseidon_gadget(
            abs_row,
            [first_wire, last_wire],
            &round_constants,
        );
        gates.extend(poseidon);
        abs_row = row;
    }

    // witness for Poseidon permutation custom constraints
    let mut witness: [Vec<Fp>; COLUMNS] =
        array::from_fn(|_| vec![Fp::zero(); POS_ROWS_PER_HASH * NUM_POS + 1 /* last output row */]);

    // creates a random input
    let input = [Fp::from(1u32), Fp::from(2u32), Fp::from(3u32)];

    // number of poseidon instances in the circuit
    for h in 0..NUM_POS {
        // index
        let first_row = h * (POS_ROWS_PER_HASH + 1);

        polynomials::poseidon::generate_witness(
            first_row,
            Vesta::sponge_params(),
            &mut witness,
            input,
        );
    }

    TestFramework::<FULL_ROUNDS, Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

fn build_poseidon_instance(
    inputs: Vec<[Fp; SPONGE_WIDTH]>,
) -> (Vec<CircuitGate<Fp>>, [Vec<Fp>; COLUMNS]) {
    let rounds = Vesta::sponge_params().round_constants;
    let rows_per = POS_ROWS_PER_HASH + 1;
    let mut gates = Vec::with_capacity(inputs.len() * rows_per);
    let mut abs_row = 0;

    for _ in &inputs {
        let first_wire = Wire::for_row(abs_row);
        let last_wire = Wire::for_row(abs_row + POS_ROWS_PER_HASH);
        let (poseidon, _) =
            CircuitGate::<Fp>::create_poseidon_gadget(abs_row, [first_wire, last_wire], &rounds);
        gates.extend(poseidon);
        abs_row += rows_per;
    }

    let mut witness: [Vec<Fp>; COLUMNS] =
        array::from_fn(|_| vec![Fp::zero(); inputs.len() * rows_per]);
    for (i, input) in inputs.into_iter().enumerate() {
        let first_row = i * rows_per;
        polynomials::poseidon::generate_witness(
            first_row,
            Vesta::sponge_params(),
            &mut witness,
            input,
        );
    }

    (gates, witness)
}

// Test that Poseidon in circuit on Kimchi expects unique inputs as a list of
// triples so that padding with zeros changes the output and the circuit
// structure itself.
#[test]
// Test that Poseidon in circuit treats an extra zero block as a distinct input,
// i.e. different circuit structure / vk.
fn test_poseidon_in_circuit_extra_zero_block() {
    // 1 block vs 2 blocks (second is all zeros)
    let (gates1, witness1) =
        build_poseidon_instance(vec![[Fp::from(1u32), Fp::from(2u32), Fp::from(3u32)]]);
    let (gates2, witness2) = build_poseidon_instance(vec![
        [Fp::from(1u32), Fp::from(2u32), Fp::from(3u32)],
        [Fp::zero(), Fp::zero(), Fp::zero()],
    ]);

    assert!(gates2.len() > gates1.len());

    let index1 = new_index_for_test::<FULL_ROUNDS, Vesta>(gates1, 0);
    let index2 = new_index_for_test::<FULL_ROUNDS, Vesta>(gates2, 0);

    let group_map = <Vesta as CommitmentCurve>::Map::setup();

    let proof1: ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS> =
        ProverProof::create::<BaseSponge, ScalarSponge, _>(
            &group_map,
            witness1,
            &[],
            &index1,
            &mut OsRng,
        )
        .unwrap();

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &index1.verifier_index(),
        &proof1,
        &[],
    )
    .expect("single-block circuit proof should verify with its vk");

    let proof2: ProverProof<Vesta, OpeningProof<Vesta, FULL_ROUNDS>, FULL_ROUNDS> =
        ProverProof::create::<BaseSponge, ScalarSponge, _>(
            &group_map,
            witness2,
            &[],
            &index2,
            &mut OsRng,
        )
        .unwrap();

    verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
        &group_map,
        &index2.verifier_index(),
        &proof2,
        &[],
    )
    .expect("two-block circuit proof should verify with its vk");

    let bad = verify::<
        FULL_ROUNDS,
        Vesta,
        BaseSponge,
        ScalarSponge,
        OpeningProof<Vesta, FULL_ROUNDS>,
    >(&group_map, &index1.verifier_index(), &proof2, &[]);
    assert!(
        bad.is_err(),
        "two-block proof must not verify with single-block vk"
    );
}
