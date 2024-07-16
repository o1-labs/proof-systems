use arrabiata::{interpreter, witness::Env};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
// FIXME: use other parameters, like one with the partial rounds
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;

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
    let srs_log2_size = matches.get_one::<usize>("srs-size").unwrap_or(&16);

    println!("Instantiating environment to execute square-root {n_iteration} times with SRS of size 2^{srs_log2_size}");

    let mut env = Env::<Fp, Fq, PlonkSpongeConstantsKimchi, Vesta, Pallas>::new(*srs_log2_size);

    while env.current_iteration < *n_iteration {
        println!("Run iteration: {}", env.current_iteration);
        for _i in 0..1_000 {
            interpreter::run_app(&mut env);
        }
        // FIXME:
        // - if i % 2 == 0, commit with e2.
        // - if i % 2 == 1, commit with e1.
        // FIXME:
        // update current instance with the previous "next" commitments (i.e. env.next_commitments)
        // update next instance with current commitments
        env.current_iteration += 1;
    }
}
