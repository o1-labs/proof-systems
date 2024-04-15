use ark_bn254::FrParameters;
use ark_ec::bn::Bn;
use ark_ff::{Fp256, UniformRand, Zero};
use kimchi::o1_utils;
use kimchi_msm::{
    columns::Column, proof::ProofInputs, prover::prove, verifier::verify, witness::Witness,
};
use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    keccak::column::{KeccakWitness, ZKVM_KECCAK_COLS},
    lookups::LookupTableIDs,
    mips::{
        column::{MIPSWitness, MIPSWitnessTrait, MIPS_COLUMNS},
        witness::{self as mips_witness, SCRATCH_SIZE},
    },
    preimage_oracle::PreImageOracle,
    proof, DOMAIN_SIZE,
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;
use std::{fs::File, io::BufReader, process::ExitCode};

type Fp = ark_bn254::Fr;
type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type OpeningProof = PairingProof<Bn<ark_bn254::Parameters>>;

pub fn main() -> ExitCode {
    let cli = cannon_cli::main_cli();

    let configuration = cannon_cli::read_configuration(&cli.get_matches());

    let file =
        File::open(&configuration.input_state_file).expect("Error opening input state file ");

    let reader = BufReader::new(file);
    // Read the JSON contents of the file as an instance of `State`.
    let state: State = serde_json::from_reader(reader).expect("Error reading input state file");

    let meta_file = File::open(&configuration.metadata_file).unwrap_or_else(|_| {
        panic!(
            "Could not open metadata file {}",
            &configuration.metadata_file
        )
    });

    let meta: Meta = serde_json::from_reader(BufReader::new(meta_file)).unwrap_or_else(|_| {
        panic!(
            "Error deserializing metadata file {}",
            &configuration.metadata_file
        )
    });

    let mut po = PreImageOracle::create(&configuration.host);
    let _child = po.start();

    // Initialize some data used for statistical computations
    let start = Start::create(state.step as usize);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let domain =
        kimchi::circuits::domains::EvaluationDomains::<ark_bn254::Fr>::create(DOMAIN_SIZE).unwrap();

    let mut rng = o1_utils::tests::make_test_rng();

    let srs = {
        // Trusted setup toxic waste
        let x = ark_bn254::Fr::rand(&mut rand::rngs::OsRng);

        let mut srs = poly_commitment::pairing_proof::PairingSRS::create(x, DOMAIN_SIZE);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    let mut env = mips_witness::Env::<ark_bn254::Fr>::create(cannon::PAGE_SIZE as usize, state, po);

    let mut mips_folded_witness = ProofInputs::<
        MIPS_COLUMNS,
        ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
        LookupTableIDs,
    >::default();

    let mips_reset_pre_folding_witness = |witness_columns: &mut MIPSWitness<Vec<_>>| {
        let MIPSWitness { cols } = witness_columns;
        // Resize without deallocating
        cols.iter_mut().for_each(Vec::clear);
    };

    let mut mips_current_pre_folding_witness = MIPSWitness {
        cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE))),
    };

    // The keccak environment is extracted inside the loop

    let mut keccak_folded_witness = ProofInputs::<
        ZKVM_KECCAK_COLS,
        ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
        LookupTableIDs,
    >::default();

    let keccak_reset_pre_folding_witness =
        |keccak_columns: &mut KeccakWitness<Vec<Fp256<FrParameters>>>| {
            // Resize without deallocating
            keccak_columns.cols.iter_mut().for_each(Vec::clear);
        };

    let mut keccak_current_pre_folding_witness: KeccakWitness<Vec<Fp256<FrParameters>>> =
        KeccakWitness {
            cols: Box::new(std::array::from_fn(|_| Vec::with_capacity(DOMAIN_SIZE))),
        };

    while !env.halt {
        env.step(&configuration, &meta, &start);

        if let Some(ref mut keccak_env) = env.keccak_env {
            // Run all steps of hash
            while keccak_env.constraints_env.step.is_some() {
                keccak_env.step();
            }

            // Update the witness with the Keccak step columns before resetting the environment
            // TODO: simplify the contents of the KeccakWitness or create an iterator for it
            for (env_wit, pre_fold_wit) in keccak_env
                .witness_env
                .witness
                .cols
                .iter()
                .zip(keccak_current_pre_folding_witness.cols.iter_mut())
            {
                pre_fold_wit.push(*env_wit);
            }

            if keccak_current_pre_folding_witness.cols.len() == DOMAIN_SIZE {
                proof::fold::<ZKVM_KECCAK_COLS, _, OpeningProof, BaseSponge, ScalarSponge>(
                    domain,
                    &srs,
                    &mut keccak_folded_witness,
                    &keccak_current_pre_folding_witness,
                );
                keccak_reset_pre_folding_witness(&mut keccak_current_pre_folding_witness);
            }

            // TODO: create READ lookup tables

            // When the Keccak interpreter is finished, we can reset the environment
            env.keccak_env = None;
        }

        // TODO: unify witness of MIPS to include the instruction and the error
        for i in 0..MIPS_COLUMNS {
            if i < SCRATCH_SIZE {
                mips_current_pre_folding_witness.cols[i].push(env.scratch_state[i]);
            } else if i == MIPS_COLUMNS - 2 {
                mips_current_pre_folding_witness.cols[i]
                    .push(ark_bn254::Fr::from(env.instruction_counter));
            } else {
                // TODO: error
                mips_current_pre_folding_witness.cols[i]
                    .push(ark_bn254::Fr::rand(&mut rand::rngs::OsRng));
            }
        }

        if mips_current_pre_folding_witness.instruction_counter().len() == DOMAIN_SIZE {
            proof::fold::<MIPS_COLUMNS, _, OpeningProof, BaseSponge, ScalarSponge>(
                domain,
                &srs,
                &mut mips_folded_witness,
                &mips_current_pre_folding_witness,
            );
            mips_reset_pre_folding_witness(&mut mips_current_pre_folding_witness);
        }
    }
    if !mips_current_pre_folding_witness
        .instruction_counter()
        .is_empty()
    {
        let remaining = DOMAIN_SIZE - mips_current_pre_folding_witness.instruction_counter().len();
        for col in mips_current_pre_folding_witness.cols.iter_mut() {
            col.extend((0..remaining).map(|_| ark_bn254::Fr::zero()));
        }
        proof::fold::<MIPS_COLUMNS, _, OpeningProof, BaseSponge, ScalarSponge>(
            domain,
            &srs,
            &mut mips_folded_witness,
            &mips_current_pre_folding_witness,
        );
    }

    {
        // MIPS
        // TODO: use actual constraints, not just an empty vector
        // FIXME: this means create separate MIPS witnesses and prove the corresponding constraints for each
        let mips_result = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            MIPS_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &vec![], mips_folded_witness, &mut rng);
        let mips_proof = mips_result.unwrap();
        println!("Generated a MIPS proof:\n{:?}", mips_proof);
        let mips_verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, MIPS_COLUMNS, 0, LookupTableIDs>(
                domain,
                &srs,
                &vec![],
                &mips_proof,
                Witness::zero_vec(DOMAIN_SIZE),
            );
        if mips_verifies {
            println!("The MIPS proof verifies")
        } else {
            println!("The MIPS proof doesn't verify")
        }
    }

    {
        // KECCAK
        // TODO: use actual constraints, not just an empty vector
        // FIXME: this means create separate Keccak witnesses and prove the corresponding constraints for each
        // FIXME: when folding is applied, the error term will be created to satisfy the folded witness
        let keccak_result = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            ZKVM_KECCAK_COLS,
            LookupTableIDs,
        >(domain, &srs, &vec![], keccak_folded_witness, &mut rng);
        let keccak_proof = keccak_result.unwrap();
        println!("Generated a proof:\n{:?}", keccak_proof);
        let keccak_verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            ZKVM_KECCAK_COLS,
            0,
            LookupTableIDs,
        >(
            domain,
            &srs,
            &vec![],
            &keccak_proof,
            Witness::zero_vec(DOMAIN_SIZE),
        );
        if keccak_verifies {
            println!("The Keccak proof verifies")
        } else {
            println!("The Keccak proof doesn't verify")
        }
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
