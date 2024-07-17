use std::time::Instant;

use ark_poly::Evaluations;
use arrabiata::{
    constraints,
    interpreter::{self},
    witness::Env,
    MIN_SRS_LOG2_SIZE,
};
use log::{debug, info};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use o1_utils::field_helpers::FieldHelpers;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
// FIXME: use other parameters, like one with the partial rounds
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use poly_commitment::{PolyComm, SRS};

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
    let mut env = Env::<Fp, Fq, PlonkSpongeConstantsKimchi, Vesta, Pallas>::new(*srs_log2_size);

    while env.current_iteration < *n_iteration {
        let start_iteration = Instant::now();

        info!("Run iteration: {}/{}", env.current_iteration, n_iteration);
        for _i in 0..domain_size {
            interpreter::run_app(&mut env);
        }

        debug!(
            "Witness for iteration {i} computed in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        // FIXME:
        // - if i % 2 == 0, commit with e1.
        // - if i % 2 == 1, commit with e2.
        // FIXME:
        // update current instance with the previous "next" commitments (i.e. env.next_commitments)
        // update next instance with current commitments
        // FIXME: Check twice the updated commitments
        // FIXME: move into the environment. It is something abstract to the user.
        if env.current_iteration % 2 == 0 {
            let comms: Vec<PolyComm<Vesta>> = env
                .witness
                .par_iter()
                .map(|evals| {
                    let evals: Vec<Fp> = evals
                        .par_iter()
                        .map(|x| Fp::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), env.domain_fp.d1);
                    env.srs_e1
                        .commit_evaluations_non_hiding(env.domain_fp.d1, &evals)
                })
                .collect();
            env.previous_commitments_e1 = comms
        } else {
            let comms: Vec<PolyComm<Pallas>> = env
                .witness
                .iter()
                .map(|evals| {
                    let evals: Vec<Fq> = evals
                        .par_iter()
                        .map(|x| Fq::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), env.domain_fq.d1);
                    env.srs_e2
                        .commit_evaluations_non_hiding(env.domain_fq.d1, &evals)
                })
                .collect();
            env.previous_commitments_e2 = comms
        }

        debug!(
            "Iteration {i} fully proven in {elapsed} μs",
            i = env.current_iteration,
            elapsed = start_iteration.elapsed().as_micros()
        );

        env.reset_for_next_iteration();
        env.current_iteration += 1;
    }

    // Checking constraints, for both fields.
    info!("Creating constraints for the circuit, over the Fp field");
    let mut constraints_fp = constraints::Env::<Fp>::new();
    interpreter::run_app(&mut constraints_fp);
    assert_eq!(constraints_fp.constraints.len(), 1);
    info!(
        "Number of constraints for the Fp field: {n}",
        n = constraints_fp.constraints.len()
    );

    info!("Creating constraints for the circuit, over the Fq field");
    let mut constraints_fq = constraints::Env::<Fq>::new();
    interpreter::run_app(&mut constraints_fq);
    assert_eq!(constraints_fq.constraints.len(), 1);
    info!(
        "Number of constraints for the Fq field: {n}",
        n = constraints_fq.constraints.len()
    );
}
