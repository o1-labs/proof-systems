use ark_ec::bn::Bn;
use ark_ff::UniformRand;
use kimchi::o1_utils;
use kimchi_msm::{
    columns::Column, proof::ProofInputs, prover::prove, verifier::verify, witness::Witness,
};
use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    keccak::{self, column::ZKVM_KECCAK_COLS, environment::KeccakEnv, KeccakCircuit},
    lookups::LookupTableIDs,
    mips::{
        column::{MIPSWitnessTrait, MIPS_COLUMNS},
        constraints as mips_constraints,
        interpreter::Instruction,
        witness::{self as mips_witness, SCRATCH_SIZE},
        MIPSCircuit,
    },
    preimage_oracle::PreImageOracle,
    proof, CircuitTrait, DOMAIN_SIZE,
};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;
use std::{collections::HashMap, fs::File, io::BufReader, process::ExitCode};
use strum::IntoEnumIterator;

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

    let domain = kimchi::circuits::domains::EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let mut rng = o1_utils::tests::make_test_rng();

    let srs = {
        // Trusted setup toxic waste
        let x = Fp::rand(&mut rand::rngs::OsRng);

        let mut srs = poly_commitment::pairing_proof::PairingSRS::create(x, DOMAIN_SIZE);
        srs.full_srs.add_lagrange_basis(domain.d1);
        srs
    };

    // Initialize the environments
    // The Keccak environment is extracted inside the loop
    let mut mips_wit_env = mips_witness::Env::<Fp>::create(cannon::PAGE_SIZE as usize, state, po);
    let mut mips_con_env = mips_constraints::Env::<Fp> {
        scratch_state_idx: 0,
        constraints: Vec::new(),
        lookups: Vec::new(),
    };
    // The keccak environment is extracted inside the loop

    // Initialize the circuits. Includes pre-folding witnesses.
    let mut mips_circuit = MIPSCircuit::<Fp>::new(DOMAIN_SIZE, &mut mips_con_env);
    let mut keccak_circuit = KeccakCircuit::<Fp>::new(DOMAIN_SIZE, &mut KeccakEnv::<Fp>::default());

    // Initialize folded instances of the sub circuits
    let mut mips_folded_instance = HashMap::new();
    for instr in Instruction::iter() {
        mips_folded_instance.insert(
            instr,
            ProofInputs::<
                MIPS_COLUMNS,
                ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
                LookupTableIDs,
            >::default(),
        );
    }
    let mut keccak_folded_instance = HashMap::new();
    for step in keccak::STEPS {
        keccak_folded_instance.insert(
            step,
            ProofInputs::<
                ZKVM_KECCAK_COLS,
                ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters>,
                LookupTableIDs,
            >::default(),
        );
    }

    let mut i = 0;
    while i < 6000000 && !mips_wit_env.halt {
        let instr = mips_wit_env.step(&configuration, &meta, &start);

        if let Some(ref mut keccak_env) = mips_wit_env.keccak_env {
            // Run all steps of hash
            while keccak_env.constraints_env.step.is_some() {
                // Get the current step that will be
                let step = keccak_env.selector();
                // Run the interpreter, which sets the witness columns
                keccak_env.step();
                // Add the witness row to the Keccak circuit for this step
                keccak_circuit.push_row(step, &keccak_env.witness_env.witness.cols);

                // If the witness is full, fold it and reset the pre-folding witness
                if keccak_circuit.witness[&step].cols[0].len() == DOMAIN_SIZE {
                    proof::fold::<ZKVM_KECCAK_COLS, _, OpeningProof, BaseSponge, ScalarSponge>(
                        domain,
                        &srs,
                        keccak_folded_instance.get_mut(&step).unwrap(),
                        &keccak_circuit.witness[&step],
                    );
                    keccak_circuit.reset(step);
                }
            }
            // When the Keccak interpreter is finished, we can reset the environment
            mips_wit_env.keccak_env = None;
        }

        // TODO: unify witness of MIPS to include the instruction and the error
        for i in 0..MIPS_COLUMNS {
            if i < SCRATCH_SIZE {
                mips_circuit.witness.get_mut(&instr).unwrap().cols[i]
                    .push(mips_wit_env.scratch_state[i]);
            } else if i == MIPS_COLUMNS - 2 {
                mips_circuit.witness.get_mut(&instr).unwrap().cols[i]
                    .push(Fp::from(mips_wit_env.instruction_counter));
            } else {
                // TODO: error
                mips_circuit.witness.get_mut(&instr).unwrap().cols[i]
                    .push(Fp::rand(&mut rand::rngs::OsRng));
            }
        }

        if mips_circuit.witness[&instr].instruction_counter().len() == DOMAIN_SIZE {
            proof::fold::<MIPS_COLUMNS, _, OpeningProof, BaseSponge, ScalarSponge>(
                domain,
                &srs,
                mips_folded_instance.get_mut(&instr).unwrap(),
                &mips_circuit.witness[&instr],
            );
            mips_circuit.reset(instr);
        }
        i += 1;
    }

    // Pad any possible remaining rows if the execution was not a multiple of the domain size
    for instr in Instruction::iter() {
        let needs_folding = mips_circuit.pad(instr);
        if needs_folding {
            proof::fold::<MIPS_COLUMNS, _, OpeningProof, BaseSponge, ScalarSponge>(
                domain,
                &srs,
                mips_folded_instance.get_mut(&instr).unwrap(),
                &mips_circuit.witness[&instr],
            );
        }
    }
    for step in keccak::STEPS {
        let needs_folding = keccak_circuit.pad(step);
        if needs_folding {
            proof::fold::<ZKVM_KECCAK_COLS, _, OpeningProof, BaseSponge, ScalarSponge>(
                domain,
                &srs,
                keccak_folded_instance.get_mut(&step).unwrap(),
                &keccak_circuit.witness[&step],
            );
        }
    }

    {
        // MIPS
        for instr in Instruction::iter() {
            let mips_result = prove::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                Column,
                _,
                MIPS_COLUMNS,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &mips_circuit.constraints[&instr],
                mips_folded_instance[&instr].clone(),
                &mut rng,
            );
            let mips_proof = mips_result.unwrap();
            eprintln!("Generated a MIPS {:?} proof:\n{:?}", instr, mips_proof);
            let mips_verifies = verify::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                MIPS_COLUMNS,
                0,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &mips_circuit.constraints[&instr],
                &mips_proof,
                Witness::zero_vec(DOMAIN_SIZE),
            );
            if mips_verifies {
                eprintln!("The MIPS {:?} proof verifies", instr)
            } else {
                eprintln!("The MIPS {:?} proof doesn't verify", instr)
            }
        }
    }

    {
        // KECCAK
        // FIXME: when folding is applied, the error term will be created to satisfy the folded witness
        for step in keccak::STEPS {
            let keccak_result = prove::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                Column,
                _,
                ZKVM_KECCAK_COLS,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &keccak_circuit.constraints[&step],
                keccak_folded_instance[&step].clone(),
                &mut rng,
            );
            let keccak_proof = keccak_result.unwrap();
            eprintln!("Generated a Keccak {:?} proof:\n{:?}", step, keccak_proof);
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
                &keccak_circuit.constraints[&step],
                &keccak_proof,
                Witness::zero_vec(DOMAIN_SIZE),
            );
            if keccak_verifies {
                eprintln!("The Keccak {:?} proof verifies", step)
            } else {
                eprintln!("The Keccak {:?} proof doesn't verify", step)
            }
        }
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
