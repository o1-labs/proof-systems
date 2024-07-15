use arrabiata::{interpreter, witness::Env};
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
// FIXME: use other parameters, like one with the partial rounds
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;

pub fn main() {
    let arg_n =
        clap::arg!(--"n" <U64> "Number of iterations").value_parser(clap::value_parser!(u64));

    let cmd = clap::Command::new("cargo")
        .bin_name("cargo")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("square-root")
                .arg(arg_n)
                .arg_required_else_help(true),
        );
    let matches = cmd.get_matches();
    let matches = match matches.subcommand() {
        Some(("square-root", matches)) => matches,
        _ => unreachable!("clap should ensure we don't get here"),
    };
    let n_iteration = matches.get_one::<u64>("n").unwrap();

    let mut env = Env::<Fp, Fq, PlonkSpongeConstantsKimchi, Vesta, Pallas>::new();

    while env.current_iteration < *n_iteration {
        println!("Run iteration: {}", env.current_iteration);
        interpreter::run(&mut env);
        env.current_iteration += 1;
    }
}
