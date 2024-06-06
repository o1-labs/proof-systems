use crate::{
    keccak::{
        column::{
            Absorbs::*,
            Sponges::*,
            Steps::{self, *},
            N_ZKVM_KECCAK_COLS, N_ZKVM_KECCAK_REL_COLS, N_ZKVM_KECCAK_SEL_COLS,
        },
        environment::KeccakEnv,
        folding::KeccakConfig,
        interpreter::KeccakInterpreter,
        trace::DecomposedKeccakTrace,
        Constraint::*,
        Error, KeccakColumn,
    },
    lookups::{FixedLookupTables, LookupTable, LookupTableIDs::*},
    trace::{DecomposableTracer, Tracer},
    BaseSponge, Fp,
};
use ark_bn254::g1::Parameters;
use ark_ff::{One, Zero};
use folding::{
    checker::{ExtendedProvider, Provider},
    decomposable_folding::DecomposableFoldingScheme,
    expressions::FoldingCompatibleExprInner,
    FoldingCompatibleExpr, FoldingConfig, FoldingScheme,
};
use kimchi::{
    circuits::polynomials::keccak::{constants::RATE_IN_BYTES, Keccak},
    o1_utils::{self, FieldHelpers, Two},
};
use kimchi_msm::test::test_completeness_generic_no_lookups;
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use rand::{rngs::StdRng, Rng};
use sha3::{Digest, Keccak256};
use std::{
    array,
    collections::{BTreeMap, HashMap},
};
use strum::IntoEnumIterator;

fn create_trace_all_steps(domain_size: usize, rng: &mut StdRng) -> DecomposedKeccakTrace {
    let mut trace = <DecomposedKeccakTrace as DecomposableTracer<KeccakEnv<Fp>>>::new(
        domain_size,
        &mut KeccakEnv::<Fp>::default(),
    );
    {
        // 1 block preimages for Sponge(Absorb(Only)), Round(0), and Sponge(Squeeze)
        for _ in 0..domain_size {
            // random 1-block preimages
            let bytelength = rng.gen_range(0..RATE_IN_BYTES);
            let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();
            // Initialize the environment and run the interpreter
            let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
            while keccak_env.step.is_some() {
                let step = keccak_env.step.unwrap();
                // Create the relation witness columns
                keccak_env.step();
                match step {
                    Sponge(Absorb(Only)) | Round(0) | Sponge(Squeeze) => {
                        // Add the witness row to the circuit
                        trace.push_row(step, &keccak_env.witness_env.witness.cols);
                    }
                    _ => {}
                }
            }
        }
        // Check there is no need for padding because we reached domain_size rows for these selectors
        assert!(trace.is_full(Sponge(Absorb(Only))));
        assert!(trace.is_full(Round(0)));
        assert!(trace.is_full(Sponge(Squeeze)));

        // Add the columns of the selectors to the circuit
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Only)), domain_size);
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Round(0), domain_size);
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Squeeze), domain_size);
    }
    {
        // 3 block preimages for Sponge(Absorb(First)), Sponge(Absorb(Middle)), and Sponge(Absorb(Last))
        for _ in 0..domain_size {
            // random 3-block preimages
            let bytelength = rng.gen_range(2 * RATE_IN_BYTES..3 * RATE_IN_BYTES);
            let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();
            // Initialize the environment and run the interpreter
            let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
            while keccak_env.step.is_some() {
                let step = keccak_env.step.unwrap();
                // Create the relation witness columns
                keccak_env.step();
                match step {
                    Sponge(Absorb(First)) | Sponge(Absorb(Middle)) | Sponge(Absorb(Last)) => {
                        // Add the witness row to the circuit
                        trace.push_row(step, &keccak_env.witness_env.witness.cols);
                    }
                    _ => {}
                }
            }
        }
        // Check there is no need for padding because we reached domain_size rows for these selectors
        assert!(trace.is_full(Sponge(Absorb(First))));
        assert!(trace.is_full(Sponge(Absorb(Middle))));
        assert!(trace.is_full(Sponge(Absorb(Last))));

        // Add the columns of the selectors to the circuit
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(First)), domain_size);
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Middle)), domain_size);
        trace.set_selector_column::<N_ZKVM_KECCAK_REL_COLS>(Sponge(Absorb(Last)), domain_size);
        trace
    }
}

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
    let table_pad = LookupTable::table_pad();
    let table_round_constants = LookupTable::table_round_constants();
    let table_byte = LookupTable::table_byte();
    let table_range_check_16 = LookupTable::table_range_check_16();
    let table_sparse = LookupTable::table_sparse();
    let table_reset = LookupTable::table_reset();
    // PadLookup
    assert!(LookupTable::is_in_table(
        &table_pad,
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
        &table_pad,
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
    assert!(LookupTable::is_in_table(&table_pad, vec![Fp::from(137u32)]).is_none());
    // RoundConstantsLookup
    assert!(LookupTable::is_in_table(
        &table_round_constants,
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
        &table_round_constants,
        vec![
            Fp::from(23),                        // Round index
            Fp::from(Keccak::sparse(0x8000)[0]), // Most significant quarter of round constant
            Fp::from(Keccak::sparse(0x0000)[0]),
            Fp::from(Keccak::sparse(0x8000)[0]),
            Fp::from(Keccak::sparse(0x8008)[0]), // Least significant quarter of round constant
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(&table_round_constants, vec![Fp::from(24u32)]).is_none());
    // ByteLookup
    assert!(LookupTable::is_in_table(&table_byte, vec![Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(&table_byte, vec![Fp::from(255u32)]).is_some());
    assert!(LookupTable::is_in_table(&table_byte, vec![Fp::from(256u32)]).is_none());
    // RangeCheck16Lookup
    assert!(LookupTable::is_in_table(&table_range_check_16, vec![Fp::zero()]).is_some());
    assert!(
        LookupTable::is_in_table(&table_range_check_16, vec![Fp::from((1 << 16) - 1)]).is_some()
    );
    assert!(LookupTable::is_in_table(&table_range_check_16, vec![Fp::from(1 << 16)]).is_none());
    // SparseLookup
    assert!(LookupTable::is_in_table(&table_sparse, vec![Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(
        &table_sparse,
        vec![Fp::from(Keccak::sparse((1 << 16) - 1)[3])]
    )
    .is_some());
    assert!(LookupTable::is_in_table(&table_sparse, vec![Fp::two()]).is_none());
    // ResetLookup
    assert!(LookupTable::is_in_table(&table_reset, vec![Fp::zero(), Fp::zero()]).is_some());
    assert!(LookupTable::is_in_table(
        &table_reset,
        vec![
            Fp::from((1 << 16) - 1),
            Fp::from(Keccak::sparse(((1u128 << 64) - 1) as u64)[3])
        ]
    )
    .is_some());
    assert!(LookupTable::is_in_table(&table_reset, vec![Fp::from(1 << 16)]).is_none());
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
    while keccak_env.step.is_some() {
        let step = keccak_env.step.unwrap();
        keccak_env.step();
        // Simulate the constraints for each row
        keccak_env.witness_env.constraints(step);
        assert!(keccak_env.witness_env.errors.is_empty());
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
fn test_regression_number_of_lookups_and_constraints_and_degree() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random bytelength and preimage for Keccak of 1, 2 or 3 blocks
    // so that there can be both First, Middle, Last and Only absorbs
    let bytelength = rng.gen_range(1..400);
    let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();

    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);

    // Execute the interpreter to obtain constraints for each step
    while keccak_env.step.is_some() {
        // Current step to be executed
        let step = keccak_env.step.unwrap();

        // Push constraints for the current step
        keccak_env.constraints_env.constraints(step);
        // Push lookups for the current step
        keccak_env.constraints_env.lookups(step);

        // Checking relation constraints for each step selector
        let mut constraint_degrees: HashMap<u64, u32> = HashMap::new();
        keccak_env
            .constraints_env
            .constraints
            .iter()
            .for_each(|constraint| {
                let degree = constraint.degree(1, 0);
                let entry = constraint_degrees.entry(degree).or_insert(0);
                *entry += 1;
            });

        // Check that the number of constraints is correct for that step type
        // Check that the degrees of the constraints are correct
        // Checking lookup constraints

        match step {
            Sponge(Absorb(First)) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 537);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 332);
                // We have 1 different degrees of constraints in Absorbs::First
                assert_eq!(constraint_degrees.len(), 1);
                // 332 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 332);
            }
            Sponge(Absorb(Middle)) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 538);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 232);
                // We have 1 different degrees of constraints in Absorbs::Middle
                assert_eq!(constraint_degrees.len(), 1);
                // 232 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 232);
            }
            Sponge(Absorb(Last)) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 539);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 374);
                // We have 2 different degrees of constraints in Squeeze
                assert_eq!(constraint_degrees.len(), 2);
                // 233 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 233);
                // 136 degree-2 constraints
                assert_eq!(constraint_degrees[&2], 141);
            }
            Sponge(Absorb(Only)) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 538);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 474);
                // We have 2 different degrees of constraints in Squeeze
                assert_eq!(constraint_degrees.len(), 2);
                // 333 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 333);
                // 136 degree-2 constraints
                assert_eq!(constraint_degrees[&2], 141);
            }
            Sponge(Squeeze) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 602);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 16);
                // We have 1 different degrees of constraints in Squeeze
                assert_eq!(constraint_degrees.len(), 1);
                // 16 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 16);
            }
            Round(_) => {
                assert_eq!(keccak_env.constraints_env.lookups.len(), 1623);
                assert_eq!(keccak_env.constraints_env.constraints.len(), 389);
                // We have 2 different degrees of constraints in Round
                assert_eq!(constraint_degrees.len(), 2);
                // 384 degree-1 constraints
                assert_eq!(constraint_degrees[&1], 384);
                // 5 degree-2 constraints
                assert_eq!(constraint_degrees[&2], 5);
            }
        }
        // Execute the step updating the witness
        // (no need to happen before constraints if we are not checking the witness)
        // This updates the step for the next
        keccak_env.step();
    }
}

#[test]
fn test_keccak_witness_satisfies_lookups() {
    let mut rng = o1_utils::tests::make_test_rng();

    // Generate random preimage of 1 block for Keccak
    let preimage: Vec<u8> = (0..100).map(|_| rng.gen()).collect();

    // Initialize the environment and run the interpreter
    let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);
    while keccak_env.step.is_some() {
        let step = keccak_env.step.unwrap();
        keccak_env.step();
        keccak_env.witness_env.lookups(step);
        assert!(keccak_env.witness_env.errors.is_empty());
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
    while keccak_env.step.is_some() {
        let step = keccak_env.step.unwrap();
        keccak_env.step();
        // Store a copy of the witness to be altered later
        witness_env.push(keccak_env.witness_env.clone());
        // Make sure that the constraints of that row hold
        keccak_env.witness_env.constraints(step);
        assert!(keccak_env.witness_env.errors.is_empty());
    }
    assert_eq!(witness_env.len(), n_steps);

    // NEGATIVIZE THE WITNESS

    // Break padding constraints
    let step = Sponge(Absorb(Only));
    assert_eq!(witness_env[0].is_pad(step), Fp::one());
    // Padding can only occur in suffix[3] and suffix[4] because length is 100 bytes
    assert_eq!(witness_env[0].pad_suffix(0), Fp::zero());
    assert_eq!(witness_env[0].pad_suffix(1), Fp::zero());
    assert_eq!(witness_env[0].pad_suffix(2), Fp::zero());
    // Check that the padding blocks are corrrect
    assert_eq!(witness_env[0].block_in_padding(0), Fp::zero());
    assert_eq!(witness_env[0].block_in_padding(1), Fp::zero());
    assert_eq!(witness_env[0].block_in_padding(2), Fp::zero());
    // Force claim pad in PadBytesFlags(0), involved in suffix(0)
    assert_eq!(
        witness_env[0].witness[KeccakColumn::PadBytesFlags(0)],
        Fp::zero()
    );
    witness_env[0].witness[KeccakColumn::PadBytesFlags(0)] = Fp::from(1u32);
    // Now that PadBytesFlags(0) is 1, then block_in_padding(0) should be 0b10*
    witness_env[0].constrain_padding(step);
    // When the byte(0) is different than 0 then the padding suffix constraint also fails
    if witness_env[0].sponge_bytes()[0] != Fp::zero() {
        assert_eq!(
            witness_env[0].errors,
            vec![
                Error::Constraint(PadAtEnd),
                Error::Constraint(PaddingSuffix(0))
            ]
        );
    } else {
        assert_eq!(witness_env[0].errors, vec![Error::Constraint(PadAtEnd)]);
    }

    witness_env[0].errors.clear();

    // Break booleanity constraints
    witness_env[0].witness[KeccakColumn::PadBytesFlags(0)] = Fp::from(2u32);
    witness_env[0].constrain_booleanity(step);
    assert_eq!(
        witness_env[0].errors,
        vec![Error::Constraint(BooleanityPadding(0))]
    );
    witness_env[0].errors.clear();

    // Break absorb constraints
    witness_env[0].witness[KeccakColumn::Input(68)] += Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::SpongeNewState(68)] += Fp::from(1u32);
    witness_env[0].witness[KeccakColumn::Output(68)] += Fp::from(1u32);
    witness_env[0].constrain_absorb(step);
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
    let step = Sponge(Squeeze);
    witness_env[25].witness[KeccakColumn::Input(0)] += Fp::from(1u32);
    witness_env[25].constrain_squeeze(step);
    assert_eq!(
        witness_env[25].errors,
        vec![Error::Constraint(SqueezeShifts(0))]
    );
    witness_env[25].errors.clear();

    // Break theta constraints
    let step = Round(0);
    witness_env[1].witness[KeccakColumn::ThetaQuotientC(0)] += Fp::from(2u32);
    witness_env[1].witness[KeccakColumn::ThetaShiftsC(0)] += Fp::from(1u32);
    witness_env[1].constrain_theta(step);
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
    let state_e = witness_env[1].constrain_theta(step);
    assert!(witness_env[1].errors.is_empty());

    // Break pi-rho constraints
    witness_env[1].witness[KeccakColumn::PiRhoRemainderE(0)] += Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::PiRhoShiftsE(0)] += Fp::from(1u32);
    witness_env[1].constrain_pirho(step, state_e.clone());
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
    let state_b = witness_env[1].constrain_pirho(step, state_e);
    assert!(witness_env[1].errors.is_empty());

    // Break chi constraints
    witness_env[1].witness[KeccakColumn::ChiShiftsB(0)] += Fp::from(1u32);
    witness_env[1].witness[KeccakColumn::ChiShiftsSum(0)] += Fp::from(1u32);
    witness_env[1].constrain_chi(step, state_b.clone());
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
    let state_f = witness_env[1].constrain_chi(step, state_b);
    assert!(witness_env[1].errors.is_empty());

    // Break iota constraints
    witness_env[1].witness[KeccakColumn::Output(0)] += Fp::from(1u32);
    witness_env[1].constrain_iota(step, state_f);
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
    while keccak_env.step.is_some() {
        let step = keccak_env.step.unwrap();
        keccak_env.step();
        keccak_env.witness_env.lookups(step);
        // Store a copy of the witness
        witness_env.push(keccak_env.witness_env.clone());
    }
    assert_eq!(witness_env.len(), n_steps);

    // Check multiplicities of the padding suffixes
    assert_eq!(
        witness_env[25].multiplicities.get_mut(&PadLookup).unwrap()[135],
        1
    );
    // Check multiplicities of the round constants of Rounds 0
    assert_eq!(
        witness_env[26]
            .multiplicities
            .get_mut(&RoundConstantsLookup)
            .unwrap()[0],
        2
    );
}

// Prover/Verifier test includidng the Keccak constraints
#[test]
fn test_keccak_prover_constraints() {
    // guaranteed to have at least 30MB of stack
    stacker::grow(30 * 1024 * 1024, || {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 8;

        // Generate 3 blocks of preimage data
        let bytelength = rng.gen_range(2 * RATE_IN_BYTES..RATE_IN_BYTES * 3);
        let preimage: Vec<u8> = (0..bytelength).map(|_| rng.gen()).collect();

        // Initialize the environment and run the interpreter
        let mut keccak_env = KeccakEnv::<Fp>::new(0, &preimage);

        // Keep track of the constraints and lookups of the sub-circuits
        let mut keccak_circuit = <DecomposedKeccakTrace as DecomposableTracer<KeccakEnv<Fp>>>::new(
            domain_size,
            &mut keccak_env,
        );

        while keccak_env.step.is_some() {
            let step = keccak_env.selector();

            // Run the interpreter, which sets the witness columns
            keccak_env.step();

            // Add the witness row to the circuit
            keccak_circuit.push_row(step, &keccak_env.witness_env.witness.cols);
        }
        keccak_circuit.pad_witnesses();

        for step in Steps::iter().flat_map(|x| x.into_iter()) {
            if keccak_circuit.in_circuit(step) {
                test_completeness_generic_no_lookups::<
                    N_ZKVM_KECCAK_COLS,
                    N_ZKVM_KECCAK_REL_COLS,
                    N_ZKVM_KECCAK_SEL_COLS,
                    0,
                    _,
                >(
                    keccak_circuit[step].constraints.clone(),
                    Box::new([]),
                    keccak_circuit[step].witness.clone(),
                    domain_size,
                    &mut rng,
                );
            }
        }
    });
}

fn dummy_constraints() -> BTreeMap<Steps, Vec<FoldingCompatibleExpr<KeccakConfig>>> {
    Steps::iter()
        .flat_map(|x| x.into_iter())
        .map(|step| {
            (
                step,
                vec![FoldingCompatibleExpr::<KeccakConfig>::Atom(
                    FoldingCompatibleExprInner::Constant(Fp::zero()),
                )],
            )
        })
        .collect()
}

// (Instance, Witness)
type KeccakFoldingSide = (
    <KeccakConfig as FoldingConfig>::Instance,
    <KeccakConfig as FoldingConfig>::Witness,
);

// (Step, Left, Right)
type KeccakFoldingPair = (Steps, KeccakFoldingSide, KeccakFoldingSide);

#[test]
fn test_keccak_folding() {
    use crate::{keccak::folding::KeccakConfig, trace::Foldable, Curve};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
    use folding::{checker::Checker, expressions::FoldingCompatibleExpr};
    use kimchi::curve::KimchiCurve;
    use mina_poseidon::FqSponge;
    use poly_commitment::srs::SRS;

    // guaranteed to have at least 30MB of stack
    stacker::grow(30 * 1024 * 1024, || {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 6;

        let domain = D::<Fp>::new(domain_size).unwrap();
        let mut srs = SRS::<Curve>::create(domain_size);
        srs.add_lagrange_basis(domain);

        // Create sponge
        let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());

        // Create two instances for each selector to be folded
        let keccak_trace: [DecomposedKeccakTrace; 2] =
            array::from_fn(|_| create_trace_all_steps(domain_size, &mut rng));
        let trace = keccak_trace[0].clone();

        // Store all constraints indexed by Step
        let constraints = <DecomposedKeccakTrace as Foldable<
            N_ZKVM_KECCAK_COLS,
            KeccakConfig,
            BaseSponge,
        >>::folding_constraints(&trace);

        // DEFINITIONS OF FUNCTIONS FOR TESTING PURPOSES

        let check_instance_satisfy_constraints =
            |constraints: &[FoldingCompatibleExpr<KeccakConfig>], side: &KeccakFoldingSide| {
                let (instance, witness) = side;
                let checker = Provider::new(instance.clone(), witness.clone());
                constraints.iter().for_each(|c| {
                    checker.check(c, domain);
                });
            };

        let check_folding =
            |left: &KeccakFoldingSide,
             right: &KeccakFoldingSide,
             constraints: &[FoldingCompatibleExpr<KeccakConfig>],
             fq_sponge: &mut DefaultFqSponge<Parameters, PlonkSpongeConstantsKimchi>| {
                // Create the folding scheme ignoring selectors
                let (scheme, final_constraint) =
                    FoldingScheme::<KeccakConfig>::new(constraints.to_vec(), &srs, domain, &());

                // Fold both sides and check the constraints ignoring the selector columns
                let fout =
                    scheme.fold_instance_witness_pair(left.clone(), right.clone(), fq_sponge);

                // We should always have 0 as the degree of the constraints,
                // without selectors, they are never higher than 2 in Keccak.
                assert_eq!(scheme.get_number_of_additional_columns(), 0);

                let checker = ExtendedProvider::new(fout.folded_instance, fout.folded_witness);
                checker.check(&final_constraint, domain);
            };

        let check_decomposable_folding_pair =
            |step: Option<Steps>,
             left: &KeccakFoldingSide,
             right: &KeccakFoldingSide,
             scheme: &DecomposableFoldingScheme<KeccakConfig>,
             final_constraint: &FoldingCompatibleExpr<KeccakConfig>,
             quadri_cols: Option<usize>,
             fq_sponge: &mut DefaultFqSponge<Parameters, PlonkSpongeConstantsKimchi>| {
                let fout =
                    scheme.fold_instance_witness_pair(left.clone(), right.clone(), step, fq_sponge);

                let extra_cols = scheme.get_number_of_additional_columns();
                if let Some(quadri_cols) = quadri_cols {
                    assert!(extra_cols == quadri_cols);
                }

                // Check the constraints on the folded circuit applying selectors
                let checker = ExtendedProvider::<KeccakConfig>::new(
                    fout.folded_instance,
                    fout.folded_witness,
                );
                checker.check(final_constraint, domain);
            };

        let check_decomposable_folding =
            |pair: &KeccakFoldingPair,
             constraints: BTreeMap<Steps, Vec<FoldingCompatibleExpr<KeccakConfig>>>,
             common_constraints: Vec<FoldingCompatibleExpr<KeccakConfig>>,
             quadri_cols: Option<usize>,
             fq_sponge: &mut DefaultFqSponge<Parameters, PlonkSpongeConstantsKimchi>| {
                let (step, left, right) = pair;
                let (dec_scheme, dec_final_constraint) =
                    DecomposableFoldingScheme::<KeccakConfig>::new(
                        constraints,
                        common_constraints,
                        &srs,
                        domain,
                        &(),
                    );
                // Subcase A: Check the folded circuit of decomposable folding ignoring selectors (None)
                check_decomposable_folding_pair(
                    None,
                    left,
                    right,
                    &dec_scheme,
                    &dec_final_constraint,
                    quadri_cols,
                    fq_sponge,
                );
                // Subcase B: Check the folded circuit of decomposable folding applying selectors (Some)
                check_decomposable_folding_pair(
                    Some(*step),
                    left,
                    right,
                    &dec_scheme,
                    &dec_final_constraint,
                    quadri_cols,
                    fq_sponge,
                );
            };

        let check_decomposable_folding_mix =
            |steps: (Steps, Steps),
             fq_sponge: &mut DefaultFqSponge<Parameters, PlonkSpongeConstantsKimchi>| {
                let (dec_scheme, dec_final_constraint) =
                    DecomposableFoldingScheme::<KeccakConfig>::new(
                        constraints.clone(),
                        vec![],
                        &srs,
                        domain,
                        &(),
                    );
                let left = {
                    let fout = dec_scheme.fold_instance_witness_pair(
                        keccak_trace[0].to_folding_pair(steps.0, fq_sponge, domain, &srs),
                        keccak_trace[1].to_folding_pair(steps.0, fq_sponge, domain, &srs),
                        Some(steps.0),
                        fq_sponge,
                    );
                    let checker = ExtendedProvider::<KeccakConfig>::new(
                        fout.folded_instance,
                        fout.folded_witness,
                    );
                    (checker.instance, checker.witness)
                };
                let right = {
                    let fout = dec_scheme.fold_instance_witness_pair(
                        keccak_trace[0].to_folding_pair(steps.1, fq_sponge, domain, &srs),
                        keccak_trace[1].to_folding_pair(steps.1, fq_sponge, domain, &srs),
                        Some(steps.1),
                        fq_sponge,
                    );
                    let checker = ExtendedProvider::<KeccakConfig>::new(
                        fout.folded_instance,
                        fout.folded_witness,
                    );
                    (checker.instance, checker.witness)
                };
                let fout = dec_scheme.fold_instance_witness_pair(left, right, None, fq_sponge);
                let checker = ExtendedProvider::new(fout.folded_instance, fout.folded_witness);
                checker.check(&dec_final_constraint, domain);
            };

        // HERE STARTS THE TESTING

        // Sanity checks that the number of constraints are as expected for each step
        assert_eq!(constraints[&Sponge(Absorb(First))].len(), 332);
        assert_eq!(constraints[&Sponge(Absorb(Middle))].len(), 232);
        assert_eq!(constraints[&Sponge(Absorb(Last))].len(), 374);
        assert_eq!(constraints[&Sponge(Absorb(Only))].len(), 474);
        assert_eq!(constraints[&Sponge(Squeeze)].len(), 16);
        assert_eq!(constraints[&Round(0)].len(), 389);

        // Total number of Keccak constraints of degree higher than 2 (should be 0)
        let total_deg_higher_2 = Steps::iter()
            .flat_map(|x| x.into_iter())
            .fold(0, |acc, step| {
                acc + trace[step]
                    .constraints
                    .iter()
                    .filter(|c| c.degree(1, 0) > 2)
                    .count()
            });
        assert_eq!(total_deg_higher_2, 0);

        // Check folding constraints of individual steps ignoring selectors
        for step in Steps::iter().flat_map(|x| x.into_iter()) {
            // BTreeMap with constraints of this step
            let mut step_constraints = BTreeMap::new();
            step_constraints.insert(step, constraints[&step].clone());

            // Create sides for folding
            let left = keccak_trace[0].to_folding_pair(step, &mut fq_sponge, domain, &srs);
            let right = keccak_trace[1].to_folding_pair(step, &mut fq_sponge, domain, &srs);

            // CASE 0: Check instances satisfy the constraints, without folding them
            check_instance_satisfy_constraints(&constraints[&step], &left);
            check_instance_satisfy_constraints(&constraints[&step], &right);

            // CASE 1: Check constraints on folded circuit ignoring selectors with `FoldingScheme`
            check_folding(&left, &right, &constraints[&step], &mut fq_sponge);

            // CASE 2: Check that `DecomposableFoldingScheme` works when passing the dummy zero constraint
            //         to each step, and an empty list of common constraints.
            let pair = (step, left, right);
            check_decomposable_folding(&pair, dummy_constraints(), vec![], Some(0), &mut fq_sponge);

            // CASE 3: Using a separate `DecomposableFoldingScheme` for each step, check each step
            //         constraints using a dummy BTreeMap of `vec[0]` per-step constraints and
            //         common constraints set to each selector's constraints.
            check_decomposable_folding(
                &pair,
                dummy_constraints(),
                step_constraints[&step].clone(),
                Some(0),
                &mut fq_sponge,
            );

            // CASE 4: Using the same `DecomposableFoldingScheme` for all steps, initialized with a real
            //         BTreeMap of only the current step, and common constraints set to `vec[]`, check
            //         the folded circuit
            check_decomposable_folding(
                &pair,
                step_constraints.clone(),
                vec![],
                None,
                &mut fq_sponge,
            );

            // CASE 5: Using the same `DecomposableFoldingScheme` for all steps, initialized with a real
            //         BTreeMap of constraints per-step, and common constraints set to `vec[]`, check
            //         the folded circuit
            check_decomposable_folding(
                &pair,
                constraints.clone(),
                vec![],
                Some(151),
                &mut fq_sponge,
            );
        }
        // CASE 6: Fold mixed steps together and check the final constraints
        check_decomposable_folding_mix((Sponge(Absorb(First)), Round(0)), &mut fq_sponge);
    });
}
