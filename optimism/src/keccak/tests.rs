use crate::{
    keccak::{
        environment::KeccakEnv, interpreter::KeccakInterpreter, Constraint::*, Error, KeccakColumn,
    },
    lookups::{FixedLookupTables, LookupTable, LookupTableIDs::*},
};
use ark_ff::{One, Zero};
use kimchi::{
    circuits::polynomials::keccak::Keccak,
    o1_utils::{self, FieldHelpers, Two},
};
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
fn test_is_in_table() {
    // PadLookup
    assert!(LookupTable::is_in_table(
        PadLookup,
        vec![
            Fp::one(),      // Length of padding
            Fp::two_pow(1), // 2^length of padding
            Fp::zero(),     // Most significant chunk of padding suffix
            Fp::zero(),
            Fp::zero(),
            Fp::zero(),
            Fp::from(0x81) // Least significant chunk of padding suffix
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(
        PadLookup,
        vec![
            Fp::from(136),                            // Length of padding
            Fp::two_pow(136),                         // 2^length of padding
            Fp::from(0x010000000000000000000000u128), // Most significant chunk of padding suffix
            Fp::zero(),
            Fp::zero(),
            Fp::zero(),
            Fp::from(0x80) // Least significant chunk of padding suffix
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(PadLookup, vec![Fp::from(137u32)]).is_none());
    // RoundConstantsLookup
    assert!(LookupTable::is_in_table(
        RoundConstantsLookup,
        vec![
            Fp::zero(), // Round index
            Fp::zero(), // Most significant quarter of round constant
            Fp::zero(),
            Fp::zero(),
            Fp::one() // Least significant quarter of round constant
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(
        RoundConstantsLookup,
        vec![
            Fp::from(23),                        // Round index
            Fp::from(Keccak::sparse(0x8000)[0]), // Most significant quarter of round constant
            Fp::from(Keccak::sparse(0x0000)[0]),
            Fp::from(Keccak::sparse(0x8000)[0]),
            Fp::from(Keccak::sparse(0x8008)[0]), // Least significant quarter of round constant
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(RoundConstantsLookup, vec![Fp::from(24u32)]).is_none());
    // ByteLookup
    assert!(LookupTable::is_in_table(ByteLookup, vec![Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(ByteLookup, vec![Fp::from(255u32)]).is_some());
    assert!(LookupTable::is_in_table(ByteLookup, vec![Fp::from(256u32)]).is_none());
    // RangeCheck16Lookup
    assert!(LookupTable::is_in_table(RangeCheck16Lookup, vec![Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(RangeCheck16Lookup, vec![Fp::from((1 << 16) - 1)]).is_some());
    assert!(LookupTable::is_in_table(RangeCheck16Lookup, vec![Fp::from(1 << 16)]).is_none());
    // SparseLookup
    assert!(LookupTable::is_in_table(SparseLookup, vec![Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(
        SparseLookup,
        vec![Fp::from(Keccak::sparse((1 << 16) - 1)[3])]
    )
    .is_some());
    assert!(LookupTable::is_in_table(SparseLookup, vec![Fp::two()]).is_none());
    // ResetLookup
    assert!(LookupTable::is_in_table(ResetLookup, vec![Fp::zero(), Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(
        ResetLookup,
        vec![
            Fp::from((1 << 16) - 1),
            Fp::from(Keccak::sparse(((1u128 << 64) - 1) as u64)[3])
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(ResetLookup, vec![Fp::from(1 << 16)]).is_none());
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
fn test_keccak_witness_satisfies_lookups() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random preimage of 1 block for Keccak
    let preimage: Vec<u8> = (0..100).map(|_| rng.gen()).collect();

    // Initialize the environment and run the interpreter
    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
    let mut i = 0;
    while keccak_env.keccak_step.is_some() {
        keccak_env.step();
        // Simulate the lookups only for absorb, last round, and squeeze because it is too slow for now
        if i == 0 || i == 24 || i == 25 {
            keccak_env.witness_env.lookups();
            assert!(keccak_env.witness_env.errors.is_empty());
        }
        i += 1;
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

    // NEGATIVIZE THE WITNESS

    // Break padding constraints
    witness_env[0].witness[KeccakColumn::PadBytesFlags(0)] = Fp::from(1u32);
    witness_env[0].constrain_padding();
    assert_eq!(
        witness_env[0].errors,
        vec![
            Error::Constraint(PadAtEnd),
            Error::Constraint(PaddingSuffix(0))
        ]
    );
    witness_env[0].errors.clear();

    // Break booleanity constraints
    witness_env[0].witness[KeccakColumn::FlagAbsorb] = Fp::from(2u32);
    witness_env[0].witness[KeccakColumn::FlagSqueeze] = Fp::from(2u32);
    witness_env[0].witness[KeccakColumn::FlagRoot] = Fp::from(2u32);
    witness_env[0].witness[KeccakColumn::PadBytesFlags(0)] = Fp::from(2u32);
    witness_env[0].constrain_booleanity();
    assert_eq!(
        witness_env[0].errors,
        vec![
            Error::Constraint(BooleanityAbsorb),
            Error::Constraint(BooleanitySqueeze),
            Error::Constraint(BooleanityRoot),
            Error::Constraint(BooleanityPadding(0))
        ]
    );
    witness_env[0].errors.clear();

    // Break mutex constraints
    witness_env[0].witness[KeccakColumn::FlagAbsorb] = Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::FlagSqueeze] = Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::FlagRound] = Fp::from(1u32);
    witness_env[0].constrain_mutex();
    assert_eq!(
        witness_env[0].errors,
        vec![
            Error::Constraint(MutexSqueezeRoot),
            Error::Constraint(MutexSqueezePad),
            Error::Constraint(MutexRoundPad),
            Error::Constraint(MutexRoundRoot),
            Error::Constraint(MutexAbsorbSqueeze)
        ]
    );
    witness_env[0].errors.clear();

    // Break absorb constraints
    witness_env[0].witness[KeccakColumn::Input(68)] += Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::SpongeNewState(68)] += Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::Output(68)] += Fp::from(1u32);
    witness_env[0].constrain_absorb();
    assert_eq!(
        witness_env[0].errors,
        vec![
            Error::Constraint(AbsorbZeroPad(0)), // 68th SpongeNewState is the 0th SpongeZeros
            Error::Constraint(AbsorbRootZero(68)),
            Error::Constraint(AbsorbXor(68)),
            Error::Constraint(AbsorbShifts(68)),
        ]
    );
    witness_env[0].errors.clear();

    // Break squeeze constraints
    witness_env[25].witness[KeccakColumn::Input(0)] += Fp::from(1u32);
    witness_env[25].constrain_squeeze();
    assert_eq!(
        witness_env[25].errors,
        vec![Error::Constraint(SqueezeShifts(0))]
    );
    witness_env[25].errors.clear();

    // Break theta constraints
    witness_env[1].witness[KeccakColumn::ThetaQuotientC(0)] += Fp::from(2u32);
    witness_env[1].witness[KeccakColumn::ThetaShiftsC(0)] += Fp::from(1u32);
    witness_env[1].constrain_theta();
    assert_eq!(
        witness_env[1].errors,
        vec![
            Error::Constraint(ThetaWordC(0)),
            Error::Constraint(ThetaRotatedC(0)),
            Error::Constraint(ThetaQuotientC(0)),
            Error::Constraint(ThetaShiftsC(0, 0))
        ]
    );
    witness_env[1].errors.clear();
    witness_env[1].witness[KeccakColumn::ThetaQuotientC(0)] -= Fp::from(2u32);
    witness_env[1].witness[KeccakColumn::ThetaShiftsC(0)] -= Fp::from(1u32);
    let state_e = witness_env[1].constrain_theta();
    assert!(witness_env[1].errors.is_empty());

    // Break pi-rho constraints
    witness_env[1].witness[KeccakColumn::PiRhoRemainderE(0)] += Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::PiRhoShiftsE(0)] += Fp::from(1u32);
    witness_env[1].constrain_pirho(state_e.clone());
    assert_eq!(
        witness_env[1].errors,
        vec![
            Error::Constraint(PiRhoWordE(0, 0)),
            Error::Constraint(PiRhoRotatedE(0, 0)),
            Error::Constraint(PiRhoShiftsE(0, 0, 0)),
        ]
    );
    witness_env[1].errors.clear();
    witness_env[1].witness[KeccakColumn::PiRhoRemainderE(0)] -= Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::PiRhoShiftsE(0)] -= Fp::from(1u32);
    let state_b = witness_env[1].constrain_pirho(state_e);
    assert!(witness_env[1].errors.is_empty());

    // Break chi constraints
    witness_env[1].witness[KeccakColumn::ChiShiftsB(0)] += Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::ChiShiftsSum(0)] += Fp::from(1u32);
    witness_env[1].constrain_chi(state_b.clone());
    assert_eq!(
        witness_env[1].errors,
        vec![
            Error::Constraint(ChiShiftsB(0, 0, 0)),
            Error::Constraint(ChiShiftsSum(0, 0, 0)),
            Error::Constraint(ChiShiftsSum(0, 3, 0)),
            Error::Constraint(ChiShiftsSum(0, 4, 0)),
        ]
    );
    witness_env[1].errors.clear();
    witness_env[1].witness[KeccakColumn::ChiShiftsB(0)] -= Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::ChiShiftsSum(0)] -= Fp::from(1u32);
    let state_f = witness_env[1].constrain_chi(state_b);
    assert!(witness_env[1].errors.is_empty());

    // Break iota constraints
    witness_env[1].witness[KeccakColumn::Output(0)] += Fp::from(1u32);
    witness_env[1].constrain_iota(state_f);
    assert_eq!(
        witness_env[1].errors,
        vec![Error::Constraint(IotaStateG(0))]
    );
    witness_env[1].errors.clear();
}

#[test]
fn test_keccak_multiplicities() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random preimage of 1 block for Keccak, which will need a second full block for padding
    let preimage: Vec<u8> = (0..136).map(|_| rng.gen()).collect();

    // Initialize witness for
    // - 1 root absorb
    // - 24 rounds
    // - 1 pad absorb
    // - 24 rounds
    // - 1 squeeze
    let n_steps = 51;
    let mut witness_env = Vec::with_capacity(n_steps);

    // Run the interpreter and keep track of the witness
    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
    while keccak_env.keccak_step.is_some() {
        keccak_env.step();
        // Run only the iota lookups because it is too slow for now
        keccak_env.witness_env.lookups_round_iota();
        // Store a copy of the witness
        witness_env.push(keccak_env.witness_env.clone());
    }
    assert_eq!(witness_env.len(), n_steps);

    // Check multiplicities of the padding suffixes
    witness_env[25].lookups_sponge();
    assert_eq!(witness_env[25].multiplicities[PadLookup as usize][135], 1);
    // Check multiplicities of the round constants of Rounds 0
    assert_eq!(
        witness_env[26].multiplicities[RoundConstantsLookup as usize][0],
        2
    );
}
