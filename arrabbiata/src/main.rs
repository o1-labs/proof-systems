//! This file contains an entry point to run a zkApp written in Rust.
//! Until the first version is complete, this file will contain code that
//! will need to be moved later into the Arrabbiata library.
//! The end goal is to allow the end-user to simply select the zkApp they want,
//! specify the number of iterations, and keep this file relatively simple.

use arrabbiata::{
    curve::PlonkSpongeConstants,
    interpreter::{self, InterpreterEnv},
    witness::Env,
    MIN_SRS_LOG2_SIZE, VERIFIER_CIRCUIT_SIZE,
};
use log::{debug, info};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::constants::SpongeConstants;
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
        "SRS size must be at least 2^{MIN_SRS_LOG2_SIZE} to support the verifier circuit size"
    );

    info!("Instantiating environment to execute square-root {n_iteration} times with SRS of size 2^{srs_log2_size}");

    let domain_size = 1 << srs_log2_size;

    // FIXME: setup correctly the initial sponge state
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    // FIXME: make a setup phase to build the selectors
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        *srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    let n_iteration_per_fold = domain_size - VERIFIER_CIRCUIT_SIZE;

    while env.current_iteration < *n_iteration {
        let start_iteration = Instant::now();

        info!("Run iteration: {}/{}", env.current_iteration, n_iteration);

        // Build the application circuit
        info!("Running {n_iteration_per_fold} iterations of the application circuit");
        for _i in 0..n_iteration_per_fold {
            interpreter::run_app(&mut env);
            env.reset();
        }

        info!(
            "Building the verifier circuit. A total number of {} rows will be filled from the witness row {}",
            VERIFIER_CIRCUIT_SIZE, env.current_row,
        );
        // Build the verifier circuit
        // FIXME: Minus one as the last row of the verifier circuit is a
        // Poseidon hash, and we write on the next row. We don't want to execute
        // a new instruction for the verifier circuit here.
        for i in 0..VERIFIER_CIRCUIT_SIZE - 1 {
            let instr = env.fetch_instruction();
            debug!(
                "Running verifier row {} (instruction = {:?}, witness row = {})",
                i, instr, env.current_row
            );
            interpreter::run_ivc(&mut env, instr);
            env.current_instruction = env.fetch_next_instruction();
            env.reset();
        }
        // FIXME: additional row for the Poseidon hash
        env.reset();

        debug!(
            "Witness for iteration {i} computed in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        // Commit to the program state.
        // Depending on the iteration, either E1 or E2 will be used.
        // The environment will keep the commitments to the program state to
        // verify and accumulate it at the next iteration.
        env.commit_state();

        // Absorb the last program state.
        env.absorb_state();

        // ----- Permutation argument -----
        // FIXME:
        // Coin chalenges β and γ for the permutation argument

        // FIXME:
        // Compute the accumulator for the permutation argument

        // FIXME:
        // Commit to the accumulator and absorb the commitment
        // ----- Permutation argument -----

        // ----- Quotient polynomial -----
        // FIXME:
        // Coin challenge α for combining the constraints
        // ----- Quotient polynomial -----

        // ----- Folding "argument" -----
        // FIXME:
        // Compute the homogeneous value `u`.

        // FIXME:
        // Compute the cross-terms

        // FIXME:
        // Absorb the cross-terms

        // FIXME:
        // Coin challenge r to fold

        // FIXME:
        // Compute the accumulated witness

        // FIXME:
        // Compute the accumulation of the commitments to the witness columns

        // FIXME:
        // Compute the accumulation of the challenges

        // FIXME:
        // Compute the accumulation of the public inputs/selectors

        // FIXME:
        // Compute the accumulation of the blinders for the PCS

        // FIXME:
        // Compute the accumulated error
        // ----- Folding "argument" -----

        debug!(
            "Iteration {i} fully proven in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        env.reset_for_next_iteration();
        env.current_iteration += 1;
    }
}
