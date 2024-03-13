use crate::keccak::{
    environment::KeccakEnv, interpreter::KeccakInterpreter, Constraint::*, Error, KeccakColumn,
};
use kimchi::o1_utils::{self, FieldHelpers};
use mina_curves::pasta::Fp;
use rand::Rng;
use sha3::{Digest, Keccak256};

#[test]
fn test_pad_blocks() {
    let blocks_1 = crate::keccak::pad_blocks::<Fp>(1);
    assert_eq!(blocks_1[0], Fp::from(0x00));
    assert_eq!(blocks_1[1], Fp::from(0x00));
    assert_eq!(blocks_1[2], Fp::from(0x00));
    assert_eq!(blocks_1[3], Fp::from(0x00));
    assert_eq!(blocks_1[4], Fp::from(0x81));

    let blocks_136 = crate::keccak::pad_blocks::<Fp>(136);
    assert_eq!(blocks_136[0], Fp::from(0x010000000000000000000000u128));
    assert_eq!(blocks_136[1], Fp::from(0x00));
    assert_eq!(blocks_136[2], Fp::from(0x00));
    assert_eq!(blocks_136[3], Fp::from(0x00));
    assert_eq!(blocks_136[4], Fp::from(0x80));
}

#[test]
fn test_keccak_witness_satisfies_constraints() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random bytelength and preimage for Keccak
    let bytelength = rng.gen_range(1..1000);
    let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();
    // Use an external library to compute the hash
    let mut hasher = Keccak256::new();
    hasher.update(&preimage);
    let hash = hasher.finalize();

    // Initialize the environment and run the interpreter
    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
    while keccak_env.keccak_step.is_some() {
        keccak_env.step();
        // Simulate the constraints for each row
        keccak_env.witness_env.constraints();
        assert!(keccak_env.witness_env.errors.is_empty());
        // Simulate the lookups for each row (it is still a no-op)
        keccak_env.witness_env.lookups();
    }
    // Extract the hash from the witness
    let output = keccak_env.witness_env.sponge_bytes()[0..32]
        .iter()
        .map(|byte| byte.to_bytes()[0])
        .collect::<Vec<_>>();

    // Check that the hash matches
    for (i, byte) in output.iter().enumerate() {
        assert_eq!(*byte, hash[i]);
    }
}

#[test]
fn test_keccak_fake_witness_wont_satisfy_constraints() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random preimage of 1 block for Keccak
    let preimage: Vec<u8> = (0..100).map(|_| rng.gen()).collect();

    // Initialize witness for
    // - 1 absorb
    // - 24 rounds
    // - 1 squeeze
    let n_steps = 26;
    let mut witness_env = Vec::with_capacity(n_steps);

    // Initialize the environment
    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);

    // Run the interpreter and keep track of the witness
    while keccak_env.keccak_step.is_some() {
        keccak_env.step();
        // Store a copy of the witness to be altered later
        witness_env.push(keccak_env.witness_env.clone());
        // Make sure that the constraints of that row hold
        keccak_env.witness_env.constraints();
        assert!(keccak_env.witness_env.errors.is_empty());
    }
    assert_eq!(witness_env.len(), n_steps);

    // Negativize mode flags in the witness
    witness_env[0].witness[KeccakColumn::FlagAbsorb] = Fp::from(2u32);
    witness_env[0].constrain_booleanity();
    assert_eq!(
        witness_env[0].errors,
        vec![Error::Constraint(BooleanityAbsorb)]
    );
}
