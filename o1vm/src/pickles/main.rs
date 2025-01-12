use ark_ff::UniformRand;
use clap::Parser;
use kimchi::circuits::domains::EvaluationDomains;
use log::debug;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1vm::{
    cannon::{self, Start, State},
    cli, elf_loader,
    interpreters::mips::{
        column::N_MIPS_REL_COLS,
        constraints as mips_constraints,
        witness::{self as mips_witness},
        Instruction,
    },
    pickles::{proof::ProofInputs, prover, verifier},
    preimage_oracle::{NullPreImageOracle, PreImageOracle, PreImageOracleT},
    test_preimage_read,
};
use poly_commitment::{ipa::SRS, SRS as _};
use std::{fs::File, io::BufReader, path::Path, process::ExitCode, time::Instant};

pub const DOMAIN_SIZE: usize = 1 << 15;

pub fn cannon_main(args: cli::cannon::RunArgs) {
    let mut rng = rand::thread_rng();

    let configuration: cannon::VmConfiguration = args.vm_cfg.into();

    let file =
        File::open(&configuration.input_state_file).expect("Error opening input state file ");

    let reader = BufReader::new(file);
    // Read the JSON contents of the file as an instance of `State`.
    let state: State = serde_json::from_reader(reader).expect("Error reading input state file");

    let meta = &configuration.metadata_file.as_ref().map(|f| {
        let meta_file =
            File::open(f).unwrap_or_else(|_| panic!("Could not open metadata file {}", f));
        serde_json::from_reader(BufReader::new(meta_file))
            .unwrap_or_else(|_| panic!("Error deserializing metadata file {}", f))
    });

    // Initialize some data used for statistical computations
    let start = Start::create(state.step as usize);

    let domain_fp = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();
    let srs: SRS<Vesta> = {
        let srs = SRS::create(DOMAIN_SIZE);
        srs.get_lagrange_basis(domain_fp.d1);
        srs
    };

    // Initialize the environments
    let mut mips_wit_env = match configuration.host.clone() {
        Some(host) => {
            let mut po = PreImageOracle::create(host);
            let _child = po.start();
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state,
                Box::new(po),
            )
        }
        None => {
            debug!("No preimage oracle provided 🤞");
            // warning: the null preimage oracle has no data and will crash the program if used
            mips_witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
                cannon::PAGE_SIZE as usize,
                state,
                Box::new(NullPreImageOracle),
            )
        }
    };

    let constraints = mips_constraints::get_all_constraints::<Fp>();

    let mut curr_proof_inputs: ProofInputs<Vesta> = ProofInputs::new(DOMAIN_SIZE);
    while !mips_wit_env.halt {
        let _instr: Instruction = mips_wit_env.step(&configuration, meta, &start);
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state_inverse
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch_inverse.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        curr_proof_inputs
            .evaluations
            .instruction_counter
            .push(Fp::from(mips_wit_env.instruction_counter));
        // FIXME: Might be another value
        curr_proof_inputs.evaluations.error.push(Fp::rand(&mut rng));

        curr_proof_inputs
            .evaluations
            .selector
            .push(Fp::from((mips_wit_env.selector - N_MIPS_REL_COLS) as u64));

        if curr_proof_inputs.evaluations.instruction_counter.len() == DOMAIN_SIZE {
            let start_iteration = Instant::now();
            debug!("Limit of {DOMAIN_SIZE} reached. We make a proof, verify it (for testing) and start with a new chunk");
            let proof = prover::prove::<
                Vesta,
                DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
                DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
                _,
            >(domain_fp, &srs, curr_proof_inputs, &constraints, &mut rng)
            .unwrap();
            // Check that the proof is correct. This is for testing purposes.
            // Leaving like this for now.
            debug!(
                "Proof generated in {elapsed} μs",
                elapsed = start_iteration.elapsed().as_micros()
            );
            {
                let start_iteration = Instant::now();
                let verif = verifier::verify::<
                    Vesta,
                    DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
                    DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
                >(domain_fp, &srs, &constraints, &proof);
                debug!(
                    "Verification done in {elapsed} μs",
                    elapsed = start_iteration.elapsed().as_micros()
                );
                assert!(verif);
            }

            curr_proof_inputs = ProofInputs::new(DOMAIN_SIZE);
        }
    }
}

fn gen_state_json(arg: cli::cannon::GenStateJsonArgs) -> Result<(), String> {
    let path = Path::new(&arg.input);
    let state = elf_loader::parse_elf(elf_loader::Architecture::Mips, path)?;
    let file = File::create(&arg.output).expect("Error creating output state file");
    serde_json::to_writer_pretty(file, &state).expect("Error writing output state file");
    Ok(())
}

pub fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Cannon(args) => match args {
            cli::cannon::Cannon::Run(args) => {
                cannon_main(args);
            }
            cli::cannon::Cannon::TestPreimageRead(args) => {
                test_preimage_read::main(args);
            }
            cli::cannon::Cannon::GenStateJson(args) => {
                gen_state_json(args).expect("Error generating state.json");
            }
        },
    }
    ExitCode::SUCCESS
}
