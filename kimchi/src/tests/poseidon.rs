#[cfg(feature = "prover")]
use {
    crate::{
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
    },
    ark_ff::Zero,
    core::array,
    groupmap::GroupMap,
    mina_curves::pasta::{Fp, Vesta, VestaParameters},
    mina_poseidon::{
        constants::{PlonkSpongeConstantsKimchi, SpongeConstants},
        pasta::FULL_ROUNDS,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    },
    o1_utils::math,
    poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof},
    rand::rngs::OsRng,
};

#[cfg(not(feature = "prover"))]
use super::generic::load_and_verify_fixture;

// aliases
#[cfg(feature = "prover")]
type SpongeParams = PlonkSpongeConstantsKimchi;
#[cfg(feature = "prover")]
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
#[cfg(feature = "prover")]
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;

#[cfg(feature = "prover")]
const NUM_POS: usize = 1; // number of Poseidon hashes in the circuit
#[cfg(feature = "prover")]
const ROUNDS_PER_HASH: usize = SpongeParams::PERM_ROUNDS_FULL;
#[cfg(feature = "prover")]
const POS_ROWS_PER_HASH: usize = ROUNDS_PER_HASH / ROUNDS_PER_ROW;
#[cfg(feature = "prover")]
const N_LOWER_BOUND: usize = (POS_ROWS_PER_HASH + 1) * NUM_POS; // Plonk domain size

#[test]
fn test_poseidon() {
    #[cfg(feature = "prover")]
    {
        let max_size = 1 << math::ceil_log2(N_LOWER_BOUND);
        println!("max_size = {max_size}");
        println!("rounds per hash = {ROUNDS_PER_HASH}");
        println!("rounds per row = {ROUNDS_PER_ROW}");
        println!(" number of rows for poseidon ={POS_ROWS_PER_HASH}");
        assert_eq!(ROUNDS_PER_HASH % ROUNDS_PER_ROW, 0);

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
        let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| {
            vec![Fp::zero(); POS_ROWS_PER_HASH * NUM_POS + 1 /* last output row */]
        });

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
            .fixture_name("test_poseidon")
            .setup()
            .prove_and_verify::<BaseSponge, ScalarSponge>()
            .unwrap();
    }

    #[cfg(not(feature = "prover"))]
    load_and_verify_fixture(include_bytes!("fixtures/test_poseidon.bin"));
}

#[cfg(feature = "prover")]
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
//
// Test that Poseidon in circuit treats an extra zero block as a distinct input,
// i.e. different circuit structure / vk.
#[test]
fn test_poseidon_in_circuit_extra_zero_block() {
    #[cfg(feature = "prover")]
    {
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

        let vi1 = index1.verifier_index();
        verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta, FULL_ROUNDS>>(
            &group_map,
            &vi1,
            &proof1,
            &[],
        )
        .expect("single-block circuit proof should verify with its vk");

        #[cfg(feature = "save-test-proofs")]
        {
            use super::fixtures::RawFixture;
            use ark_serialize::CanonicalSerialize;

            let mut endo_buf = Vec::new();
            vi1.endo.serialize_compressed(&mut endo_buf).unwrap();

            let fixture = RawFixture {
                proof_bytes: rmp_serde::to_vec(&proof1).unwrap(),
                verifier_index_bytes: rmp_serde::to_vec(&vi1).unwrap(),
                public_inputs_bytes: Vec::new(),
                num_public_inputs: 0,
                feature_flags: index1.cs.feature_flags,
                endo: Some(endo_buf),
            };

            let bytes = rmp_serde::to_vec(&fixture).unwrap();
            let fixtures_dir =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/fixtures");
            std::fs::create_dir_all(&fixtures_dir).unwrap();
            let path = fixtures_dir.join("test_poseidon_in_circuit_extra_zero_block.bin");
            std::fs::write(&path, &bytes).unwrap();
            println!("Fixture written to {}", path.display());
        }

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
        >(&group_map, &vi1, &proof2, &[]);
        assert!(
            bad.is_err(),
            "two-block proof must not verify with single-block vk"
        );
    }

    #[cfg(not(feature = "prover"))]
    load_and_verify_fixture(include_bytes!(
        "fixtures/test_poseidon_in_circuit_extra_zero_block.bin"
    ));
}
