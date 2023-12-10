use kimchi_optimism::{
    cannon::{self, Meta, Start, State},
    cannon_cli,
    mips::witness,
    preimage_oracle::PreImageOracle,
};
use std::{fs::File, io::BufReader, process::ExitCode};

pub fn main() -> ExitCode {
    let cli = cannon_cli::main_cli();

    let configuration = cannon_cli::read_configuration(&cli.get_matches());

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
