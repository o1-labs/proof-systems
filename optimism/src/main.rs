use clap::{arg, value_parser, Arg, ArgAction, Command};
use kimchi_optimism::{
    cannon::{self, Meta, Start, State, VmConfiguration},
    mips::witness,
    preimage_oracle::PreImageOracle,
};
use std::{fs::File, io::BufReader, process::ExitCode};

fn cli() -> VmConfiguration {
    use kimchi_optimism::cannon::*;

    let app_name = "zkvm";
    let cli = Command::new(app_name)
        .version("0.1")
        .about("MIPS-based zkvm")
        .arg(arg!(--input <FILE> "initial state file").default_value("state.json"))
        .arg(arg!(--output <FILE> "output state file").default_value("out.json"))
        .arg(arg!(--meta <FILE> "metadata file").default_value("meta.json"))
        // The CLI arguments below this line are ignored at this point
        .arg(
            Arg::new("proof-at")
                .short('p')
                .long("proof-at")
                .value_name("FREQ")
                .default_value("never")
                .value_parser(step_frequency_parser),
        )
        .arg(
            Arg::new("proof-fmt")
                .long("proof-fmt")
                .value_name("FORMAT")
                .default_value("proof-%d.json"),
        )
        .arg(
            Arg::new("snapshot-fmt")
                .long("snapshot-fmt")
                .value_name("FORMAT")
                .default_value("state-%d.json"),
        )
        .arg(
            Arg::new("stop-at")
                .long("stop-at")
                .value_name("FREQ")
                .default_value("never")
                .value_parser(step_frequency_parser),
        )
        .arg(
            Arg::new("info-at")
                .long("info-at")
                .value_name("FREQ")
                .default_value("never")
                .value_parser(step_frequency_parser),
        )
        .arg(
            Arg::new("pprof-cpu")
                .long("pprof-cpu")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(host: [HOST] "host program specification <host program> [host program arguments]")
                .num_args(1..)
                .last(true)
                .value_parser(value_parser!(String)),
        );

    let cli = cli.get_matches();

    let input_state_file = cli.get_one::<String>("input").unwrap();

    let output_state_file = cli.get_one::<String>("output").unwrap();

    let metadata_file = cli.get_one::<String>("meta").unwrap();

    let proof_at = cli.get_one::<StepFrequency>("proof-at").unwrap();
    let info_at = cli.get_one::<StepFrequency>("info-at").unwrap();
    let stop_at = cli.get_one::<StepFrequency>("stop-at").unwrap();

    let proof_fmt = cli.get_one::<String>("proof-fmt").unwrap();
    let snapshot_fmt = cli.get_one::<String>("snapshot-fmt").unwrap();
    let pprof_cpu = cli.get_one::<bool>("pprof-cpu").unwrap();

    let host_spec = cli
        .get_many::<String>("host")
        .map(|vals| vals.collect::<Vec<_>>())
        .unwrap_or_default();

    let host = if host_spec.is_empty() {
        None
    } else {
        Some(HostProgram {
            name: host_spec[0].to_string(),
            arguments: host_spec[1..]
                .to_vec()
                .iter()
                .map(|x| x.to_string())
                .collect(),
        })
    };

    VmConfiguration {
        input_state_file: input_state_file.to_string(),
        output_state_file: output_state_file.to_string(),
        metadata_file: metadata_file.to_string(),
        proof_at: proof_at.clone(),
        stop_at: stop_at.clone(),
        info_at: info_at.clone(),
        proof_fmt: proof_fmt.to_string(),
        snapshot_fmt: snapshot_fmt.to_string(),
        pprof_cpu: *pprof_cpu,
        host,
    }
}

pub fn main() -> ExitCode {
    let configuration = cli();

    let rng = {
        use rand::SeedableRng;
        &mut rand::rngs::StdRng::from_seed([0u8; 32])
    };

    let (srs, domain) = {
        use ark_bn254::Fr as ScalarField;
        use ark_bn254::G1Affine as G1;
        use ark_ff::UniformRand;
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
        use poly_commitment::srs::SRS;

        let n = 1 << 15;
        let domain = D::<ScalarField>::new(n).unwrap();

        let x = ScalarField::rand(rng);

        let mut srs = SRS::<G1>::create_trusted_setup(x, n);
        srs.add_lagrange_basis(domain);
        (srs, domain)
    };

    // Commitment test
    {
        use ark_ff::UniformRand;

        let evaluations: Vec<_> = (0..1 << 15).map(|_| u64::rand(rng)).collect();

        let before = std::time::SystemTime::now();

        let thread_pools: [_; 15] = std::array::from_fn(|_| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap()
        });

        let wrapping_thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();

        for _ in 0..300 {
            wrapping_thread_pool.install(|| {
                rayon::scope(|s| {
                    for thread_pool in thread_pools.iter() {
                        s.spawn(|_| {
                            let _commitment = thread_pool.install(|| {
                                srs.commit_evaluations_non_hiding_u64(domain, &evaluations)
                            });
                        });
                    }
                });
            });
        }

        let after = std::time::SystemTime::now();

        println!(
            "elapsed: {}s",
            after.duration_since(before).unwrap().as_secs_f64() / 300.0
        )
    }

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

    let mut env = witness::Env::<ark_bn254::Fr>::create(cannon::PAGE_SIZE as usize, state, po);

    let mut map = std::collections::HashMap::new();

    let mut values: [_; 60] = std::array::from_fn(|_| vec![]);


    while !env.halt {
        env.step(&configuration, &meta, &start);

        *map.entry(env.scratch_state_idx).or_insert(0) += 1;

        for i in 0..values.len() {
            values[i].push(env.scratch_state[i]);
        }

        if values[0].len() == 1 << 15 {
            use rayon::prelude::*;
            values.par_iter_mut().for_each(|evaluations| {
                use ark_poly::Evaluations;
                use poly_commitment::SRS;
                let evaluations = std::mem::take(evaluations);
                let _commitment = srs.commit_evaluations_non_hiding(
                    domain,
                    &Evaluations::from_vec_and_domain(evaluations, domain),
                );
            });
        }
    }
    for evaluations in &mut values {
        use ark_poly::Evaluations;
        use poly_commitment::SRS;
        let evaluations = std::mem::take(evaluations);
        let _commitment = srs.commit_evaluations_non_hiding(
            domain,
            &Evaluations::from_vec_and_domain(evaluations, domain),
        );
    }

    let total = map.iter().fold(0, |acc, (_, x)| acc + x);

    let average = map.iter().fold(0.0, |acc, (x, y)| {
        acc + (*x as f64) * (*y as f64) / (total as f64)
    });

    println!("Average number of allocations: {}", average);

    // TODO: Logic
    ExitCode::FAILURE
}
