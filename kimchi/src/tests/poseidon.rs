use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials,
        polynomials::poseidon::ROUNDS_PER_ROW,
        wires::{Wire, COLUMNS},
    },
    curve::KimchiCurve,
    tests::framework::TestFramework,
};
use ark_ff::Zero;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1_utils::math;
use std::array;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

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
    let round_constants = &*Vesta::sponge_params().round_constants;

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
            round_constants,
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

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}
