use ark_poly::Evaluations;
use arrabiata::{
    interpreter::{self},
    witness::Env,
    MIN_SRS_LOG2_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
// FIXME: use other parameters, like one with the partial rounds
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use poly_commitment::{PolyComm, SRS};

pub fn main() {
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

    println!("Instantiating environment to execute square-root {n_iteration} times with SRS of size 2^{srs_log2_size}");

    let domain_size = 1 << srs_log2_size;
    let mut env = Env::<Fp, Fq, PlonkSpongeConstantsKimchi, Vesta, Pallas>::new(*srs_log2_size);

    while env.current_iteration < *n_iteration {
        println!("Run iteration: {}", env.current_iteration);
        for _i in 0..domain_size {
            interpreter::run_app(&mut env);
        }
        // FIXME:
        // - if i % 2 == 0, commit with e1.
        // - if i % 2 == 1, commit with e2.
        // FIXME:
        // update current instance with the previous "next" commitments (i.e. env.next_commitments)
        // update next instance with current commitments
        // FIXME: the environment is built using Fp elements. We must handle
        // both circuits in the interpreter. Maybe having two type of witnesses?
        // We must abstract the function being executed in a certain way.
        // FIXME: Check twice the updated commitments
        if env.current_iteration % 2 == 0 {
            let comms: Vec<PolyComm<Vesta>> = env
                .witness
                .par_iter()
                .map(|evals| {
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), env.domain_fp.d1);
                    env.srs_e1
                        .commit_evaluations_non_hiding(env.domain_fp.d1, &evals)
                })
                .collect();
            env.previous_commitments_e1 = comms
        } else {
            // let comms: Vec<PolyComm<Vesta>> = env
            //     .witness
            //     .iter()
            //     .map(|evals| {
            //         let evals = Evaluations::from_vec_and_domain(evals.to_vec(), env.domain_fp.d1);
            //         env.srs_e1
            //             .commit_evaluations_non_hiding(env.domain_fp.d1, &evals)
            //     })
            //     .collect();
            // env.previous_commitments_e1 = comms
        }
        env.reset_for_next_iteration();
        env.current_iteration += 1;
    }
}
