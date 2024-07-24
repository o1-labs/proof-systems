use arrabiata::{
    interpreter::{self, InterpreterEnv},
    witness::Env,
    IVC_CIRCUIT_SIZE, MIN_SRS_LOG2_SIZE, POSEIDON_STATE_SIZE,
};
use log::{debug, info};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use std::time::Instant;

pub fn main() {
    // See https://github.com/rust-lang/log
    env_logger::init();

    let arg_n =
        clap::arg!(--"n" <U64> "Number of iterations").value_parser(clap::value_parser!(u64));

    let arg_srs_size = clap::arg!(--"srs-size" <U64> "Size of the SRS in base 2")
        .value_parser(clap::value_parser!(usize));

    let cmd = clap::Command::new("cargo")
        .bin_name("cargo")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("square-root")
                .arg(arg_n)
                .arg(arg_srs_size)
                .arg_required_else_help(true),
        );
    let matches = cmd.get_matches();
    let matches = match matches.subcommand() {
        Some(("square-root", matches)) => matches,
        _ => unreachable!("clap should ensure we don't get here"),
    };
    let n_iteration = matches.get_one::<u64>("n").unwrap();
    let srs_log2_size = matches
        .get_one::<usize>("srs-size")
        .unwrap_or(&MIN_SRS_LOG2_SIZE);

    assert!(
        *srs_log2_size >= MIN_SRS_LOG2_SIZE,
        "SRS size must be at least 2^{MIN_SRS_LOG2_SIZE} to support IVC"
    );

    info!("Instantiating environment to execute square-root {n_iteration} times with SRS of size 2^{srs_log2_size}");

    let domain_size = 1 << srs_log2_size;

    // FIXME: setup correctly the initial sponge state
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    // FIXME: make a setup phase to build the selectors
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        *srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    let n_iteration_per_fold = domain_size - IVC_CIRCUIT_SIZE;

    while env.current_iteration < *n_iteration {
        let start_iteration = Instant::now();

        info!("Run iteration: {}/{}", env.current_iteration, n_iteration);

        // Build the application circuit
        info!("Running N iterations of the application circuit");
        for _i in 0..n_iteration_per_fold {
            interpreter::run_app(&mut env);
            env.reset();
        }

        info!("Building the IVC circuit");
        // Build the IVC circuit
        for _i in 0..IVC_CIRCUIT_SIZE {
            let instr = env.fetch_instruction();
            interpreter::run_ivc(&mut env, instr);
            env.current_instruction = env.fetch_next_instruction();
            env.reset();
        }

        debug!(
            "Witness for iteration {i} computed in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        // FIXME:
        // update current instance with the previous "next" commitments (i.e.
        // env.next_commitments)
        // update next instance with current commitments
        // FIXME: Check twice the updated commitments
        env.compute_and_update_previous_commitments();

        debug!(
            "Iteration {i} fully proven in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        env.reset_for_next_iteration();
        env.current_iteration += 1;
    }
}
