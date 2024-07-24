use arrabiata::{
    interpreter::{self, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp,
    witness::Env,
    POSEIDON_ROUNDS_FULL, POSEIDON_STATE_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};
use num_bigint::BigInt;
use o1_utils::FieldHelpers;

// Used by the mina_poseidon library. Only for testing.
#[derive(Clone)]
pub struct PlonkSpongeConstants {}

impl SpongeConstants for PlonkSpongeConstants {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = POSEIDON_STATE_SIZE;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = POSEIDON_ROUNDS_FULL;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 5;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}

#[test]
fn test_unit_witness_poseidon_gadget() {
    let srs_log2_size = 6;
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );
    (0..(POSEIDON_ROUNDS_FULL / 4)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::Poseidon(4 * i));
        env.reset();
    });
    let exp_output = {
        let mut state = sponge_e1
            .clone()
            .to_vec()
            .iter()
            .map(|x| Fp::from_biguint(&x.to_biguint().unwrap()).unwrap())
            .collect::<Vec<_>>();
        poseidon_block_cipher::<Fp, PlonkSpongeConstants>(
            poseidon_3_60_0_5_5_fp::static_params(),
            &mut state,
        );
        state
            .iter()
            .map(|x| x.to_biguint().into())
            .collect::<Vec<_>>()
    };
    // Check correctness for current iteration
    assert_eq!(env.sponge_e1.to_vec(), exp_output);
    // Check the other sponge hasn't been modified
    assert_eq!(env.sponge_e2, sponge_e1.clone());
}
