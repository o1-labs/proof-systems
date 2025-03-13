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
    assert!(
        srs_log2_size >= MIN_SRS_LOG2_SIZE,
        "SRS size must be at least 2^{MIN_SRS_LOG2_SIZE} to support the verifier circuit size"
    );

    info!("Instantiating environment to execute TODO {n_iteration} times with SRS of size 2^{srs_log2_size}");

    let zkapp_fp: MinRoot<Fp> = MinRoot {
        x: Fp::from(0),
        y: Fp::from(0),
        n: 0,
    };
    let zkapp_fq: MinRoot<Fq> = MinRoot {
        x: Fq::from(0),
        y: Fq::from(0),
        n: 0,
    };

    let indexed_relation = IndexedRelation::new(zkapp_fp, zkapp_fq, srs_log2_size);

    let mut env =
        witness::Env::<Fp, Fq, Vesta, Pallas, MinRoot<Fp>, MinRoot<Fq>>::new(indexed_relation);
    env.execute(n_instruction);

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
