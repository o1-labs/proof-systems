use kimchi::circuits::domains::EvaluationDomains;
use o1vm::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    interpreters::mips::{
        constraints as mips_constraints, interpreter, witness as mips_witness, Instruction,
    },
    preimage_oracle::PreImageOracle,
    E,
};
use poly_commitment::srs::SRS;
use std::{fs::File, io::BufReader, process::ExitCode};
use strum::IntoEnumIterator;

use mina_curves::pasta::{Fp, Vesta};

pub const DOMAIN_SIZE: usize = 1 << 15;

pub fn main() -> ExitCode {
    let cli = cannon_cli::main_cli();

    let configuration = cannon_cli::read_configuration(&cli.get_matches());

    let file =
        File::open(&configuration.input_state_file).expect("Error opening input state file ");

    let reader = BufReader::new(file);
    // Read the JSON contents of the file as an instance of `State`.
    let state: State = serde_json::from_reader(reader).expect("Error reading input state file");

    let meta_file = File::open(&configuration.metadata_file).unwrap_or_else(|_| {
        panic!(
            "Could not open metadata file {}",
            &configuration.metadata_file
        )
    });

    let meta: Meta = serde_json::from_reader(BufReader::new(meta_file)).unwrap_or_else(|_| {
        panic!(
            "Error deserializing metadata file {}",
            &configuration.metadata_file
        )
    });

    let mut po = PreImageOracle::create(&configuration.host);
    let _child = po.start();

    // Initialize some data used for statistical computations
    let start = Start::create(state.step as usize);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let domain_fp = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();
    let _srs: SRS<Vesta> = {
        let mut srs = SRS::create(DOMAIN_SIZE);
        srs.add_lagrange_basis(domain_fp.d1);
        srs
    };

    // Initialize the environments
    let mut mips_wit_env =
        mips_witness::Env::<Fp, PreImageOracle>::create(cannon::PAGE_SIZE as usize, state, po);

    // TODO: smth w/ selectors
    let _all_constraints: Vec<E<Fp>> = Instruction::iter()
        .flat_map(|instr| {
            let mut env: mips_constraints::Env<Fp> = mips_constraints::Env::default();
            interpreter::interpret_instruction(&mut env, instr);
            env.constraints
        })
        .collect::<Vec<_>>();

    while !mips_wit_env.halt {
        let instr = mips_wit_env.step(&configuration, &meta, &start);
        println!("Executed instruction: {:?}", instr);
    }

    // TODO: Logic
    ExitCode::SUCCESS
}
