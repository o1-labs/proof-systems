use clap::Parser;
use log::debug;
use mina_curves::pasta::{Fp, Vesta};
use o1vm::{
    cannon::{self, Start, State},
    cli, elf_loader,
    interpreters::mips::witness::{self as mips_witness},
    pickles::{cannon_main, DOMAIN_FP, DOMAIN_SIZE},
    preimage_oracle::{NullPreImageOracle, PreImageOracle, PreImageOracleT},
    test_preimage_read,
};
use poly_commitment::{ipa::SRS, SRS as _};
use std::{fs::File, io::BufReader, path::Path, process::ExitCode};

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
                let configuration: cannon::VmConfiguration = args.vm_cfg.into();

                // Read the JSON contents of the file as an instance of `State`.
                let state: State = {
                    let file = File::open(&configuration.input_state_file)
                        .expect("Error opening input state file ");
                    let reader = BufReader::new(file);
                    serde_json::from_reader(reader).expect("Error reading input state file")
                };

                // Initialize some data used for statistical computations
                let start = Start::create(state.step as usize);

                let meta = &configuration.metadata_file.as_ref().map(|f| {
                    let meta_file = File::open(f)
                        .unwrap_or_else(|_| panic!("Could not open metadata file {}", f));
                    serde_json::from_reader(BufReader::new(meta_file))
                        .unwrap_or_else(|_| panic!("Error deserializing metadata file {}", f))
                });

                // Initialize the environments
                let mips_wit_env = match configuration.host.clone() {
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
                        srs.get_lagrange_basis(DOMAIN_FP.d1);
                        debug!("SRS created successfully");
                        srs
                    }
                };

                cannon_main(configuration, mips_wit_env, &srs, start, meta);
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
