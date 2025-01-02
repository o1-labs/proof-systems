use ark_ec::short_weierstrass::Affine;
use ark_ff::UniformRand;
use clap::Parser;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::expr::E;
use log::debug;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use o1vm::{
    cannon::{self, Meta, Start, State},
    cli, elf_loader,
    interpreters::mips::{
        column::N_MIPS_REL_COLS,
        constraints as mips_constraints,
        witness::{self as mips_witness},
        Instruction,
    },
    pickles::{
        proof::{Proof, ProofInputs},
        prover, verifier,
    },
    preimage_oracle::{NullPreImageOracle, PreImageOracle, PreImageOracleT},
    test_preimage_read,
};
use poly_commitment::{ipa::SRS, SRS as _};
use rand::rngs::ThreadRng;
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

    let srs: SRS<Vesta> = match &args.srs_cache {
        Some(cache) => {
            debug!("Loading SRS from cache {}", cache);
            let file = File::open(cache).expect("Error opening srs_cache file ");
            let reader = BufReader::new(file);
            let srs: SRS<Vesta> = rmp_serde::from_read(reader).unwrap();
            debug!("SRS loaded successfully from cache");
            srs
        }
        None => {
            debug!("No SRS cache provided. Creating SRS from scratch");
            let srs = SRS::create(DOMAIN_SIZE);
            srs.get_lagrange_basis(domain_fp.d1);
            debug!("SRS created successfully");
            srs
        }
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
        step_prover(
            &configuration,
            meta,
            &start,
            &mut rng,
            &mut mips_wit_env,
            &mut curr_proof_inputs,
        );

        if curr_proof_inputs.evaluations.instruction_counter.len() == DOMAIN_SIZE {
            debug!("Limit of {DOMAIN_SIZE} reached. We make a proof, verify it (for testing) and start with a new chunk");
            let proof = prove(domain_fp, &srs, curr_proof_inputs, &constraints, &mut rng);
            verify(domain_fp, &srs, &constraints, &proof);
            curr_proof_inputs = ProofInputs::new(DOMAIN_SIZE);
        }
    }
}

fn step_prover(
    configuration: &cannon::VmConfiguration,
    meta: &Option<Meta>,
    start: &Start,
    rng: &mut ThreadRng,
    mips_wit_env: &mut mips_witness::Env<Fp, Box<dyn PreImageOracleT>>,
    curr_proof_inputs: &mut ProofInputs<Vesta>,
) {
    let _: Instruction = mips_wit_env.step(configuration, meta, start);
    // copy over the witness data to the proof inputs
    for (i, scratch) in mips_wit_env.scratch_state.iter().enumerate() {
        curr_proof_inputs.evaluations.scratch[i].push(*scratch);
    }
    for (i, scratch) in mips_wit_env.scratch_state_inverse.iter().enumerate() {
        curr_proof_inputs.evaluations.scratch_inverse[i].push(*scratch);
    }
    curr_proof_inputs
        .evaluations
        .instruction_counter
        .push(Fp::from(mips_wit_env.instruction_counter));
    // FIXME: Might be another value
    curr_proof_inputs.evaluations.error.push(Fp::rand(rng));

    curr_proof_inputs
        .evaluations
        .selector
        .push(Fp::from((mips_wit_env.selector - N_MIPS_REL_COLS) as u64));
}

fn prove(
    domain_fp: EvaluationDomains<Fp>,
    srs: &SRS<Vesta>,
    curr_proof_inputs: ProofInputs<Vesta>,
    constraints: &[E<Fp>],
    rng: &mut ThreadRng,
) -> Proof<Affine<VestaParameters>> {
    let start_iteration = Instant::now();
    let proof = prover::prove::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        _,
    >(domain_fp, srs, curr_proof_inputs, constraints, rng)
    .unwrap();
    // FIXME: check that the proof is correct. This is for testing purposes.
    // Leaving like this for now.
    debug!(
        "Proof generated in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    proof
}

fn verify(
    domain_fp: EvaluationDomains<Fp>,
    srs: &SRS<Vesta>,
    constraints: &[E<Fp>],
    proof: &Proof<Affine<VestaParameters>>,
) {
    let start_iteration = Instant::now();
    let verif = verifier::verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
    >(domain_fp, srs, constraints, proof);
    debug!(
        "Verification done in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    assert!(verif);
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
