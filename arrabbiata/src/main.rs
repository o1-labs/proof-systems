//! This file contains an entry point to run a zkApp written in Rust.
//! Until the first version is complete, this file will contain code that
//! will need to be moved later into the Arrabbiata library.
//! The end goal is to allow the end-user to simply select the zkApp they want,
//! specify the number of iterations, and keep this file relatively simple.

use arrabbiata::{
    challenge::ChallengeTerm,
    cli,
    interpreter::{self, InterpreterEnv},
    setup::IndexedRelation,
    witness, MIN_SRS_LOG2_SIZE, VERIFIER_CIRCUIT_SIZE,
};
use clap::Parser;
use log::{debug, info};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use num_bigint::BigInt;
use std::time::Instant;

pub fn execute(args: cli::ExecuteArgs) {
    let srs_log2_size = args.srs_size;
    let n_iteration = args.n;
    let zkapp = args.zkapp;
    assert_eq!(
        zkapp, "square-root",
        "This is a dummy value for now. This argument does nothing, but it is while we're changing the CLI interface"
    );

    assert!(
        srs_log2_size >= MIN_SRS_LOG2_SIZE,
        "SRS size must be at least 2^{MIN_SRS_LOG2_SIZE} to support the verifier circuit size"
    );

    info!("Instantiating environment to execute square-root {n_iteration} times with SRS of size 2^{srs_log2_size}");

    // FIXME: correctly setup
    let indexed_relation = IndexedRelation::new(srs_log2_size);

    let mut env = witness::Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    while env.current_iteration < n_iteration {
        let start_iteration = Instant::now();

        info!("Run iteration: {}/{}", env.current_iteration, n_iteration);

        // Build the application circuit
        info!(
            "Running {} iterations of the application circuit",
            env.indexed_relation.app_size
        );
        for _i in 0..env.indexed_relation.app_size {
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
            let current_instr = env.fetch_instruction();
            debug!(
                "Running verifier row {} (instruction = {:?}, witness row = {})",
                i,
                current_instr.clone(),
                env.current_row
            );
            interpreter::run_ivc(&mut env, current_instr);
            env.current_instruction = interpreter::fetch_next_instruction(current_instr);
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

        // Coin challenge α for combining the constraints
        env.coin_challenge(ChallengeTerm::ConstraintCombiner);
        debug!(
            "Coin challenge α: 0x{chal}",
            chal = env.challenges[ChallengeTerm::ConstraintCombiner].to_str_radix(16)
        );

        // ----- Accumulation/folding argument -----
        // FIXME:
        // Compute the cross-terms

        // FIXME:
        // Absorb the cross-terms

        // Coin challenge r to fold the instances of the relation.
        // FIXME: we must do the step before first! Skipping for now to achieve
        // the next step, i.e. accumulating on the prover side the different
        // values below.
        env.coin_challenge(ChallengeTerm::RelationCombiner);
        debug!(
            "Coin challenge r: 0x{r}",
            r = env.challenges[ChallengeTerm::RelationCombiner].to_str_radix(16)
        );
        env.accumulate_program_state();

        // Compute the accumulation of the commitments to the witness columns
        env.accumulate_committed_state();

        // FIXME:
        // Compute the accumulation of the challenges

        // FIXME:
        // Compute the accumulation of the public inputs/selectors

        // FIXME:
        // Compute the accumulation of the blinders for the PCS

        // FIXME:
        // Compute the accumulated error
        // ----- Accumulation/folding argument -----

        debug!(
            "Iteration {i} fully proven in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        env.reset_for_next_iteration();
        env.current_iteration += 1;
    }

    // Regression test in case we change the Poseidon gadget or the verifier circuit.
    // These values define the state of the application at the end of the
    // execution.
    assert_eq!(
        env.challenges[ChallengeTerm::RelationCombiner].to_str_radix(16),
        "f900168373307589ea461f97f47ca7d7"
    );
    assert_eq!(
        env.challenges[ChallengeTerm::ConstraintCombiner].to_str_radix(16),
        "fc5ac212f5f89cbd3a04a3eb39ce2999"
    );
}

pub fn main() {
    // See https://github.com/rust-lang/log
    env_logger::init();

    let args = cli::Commands::parse();
    match args {
        cli::Commands::Execute(args) => execute(args),
    }
}
