use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, ProjectiveVesta, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge as _,
};
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::SRS,
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::process::ExitCode;

// To run:
// ```
// cargo run --release -p data-storage
// ```

pub fn run_main() -> ExitCode {
    const SRS_SIZE: usize = 1 << 16;

    println!("Startup time (cacheable, 1-time cost)");

    println!("- Generate SRS");
    let now = std::time::Instant::now();
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
    let srs = SRS::<Vesta>::create(SRS_SIZE);
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );
    println!("- Generate SRS lagrange basis");
    let basis = srs
        .get_lagrange_basis(domain)
        .iter()
        .map(|x| x.chunks[0])
        .collect::<Vec<_>>();
    let basis = basis.as_slice();
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("- Generate 'group map' parameters");
    let now = std::time::Instant::now();
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    const DATA_SIZE: usize = 1 << 25;

    println!("");
    println!("Set up test, not used in real system");

    println!(
        "- Generate some random data of size {} (represented as {} field elements)",
        DATA_SIZE * 32,
        DATA_SIZE
    );
    println!(
        "  - Using cryptographically-secure randomness for test vector (warning: this may be slow)"
    );
    let now = std::time::Instant::now();
    let rng = &mut rand::rngs::OsRng;
    let data = (0..DATA_SIZE)
        .map(|_| <Fp as UniformRand>::rand(rng).into_bigint())
        .collect::<Vec<_>>();
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("");
    println!("Main protocol");

    println!("- One-time setup for newly-stored data");
    println!("  - Generate cryptographic commitments");
    let now = std::time::Instant::now();
    let committed_chunks = (0..data.len() / SRS_SIZE)
        .into_par_iter()
        .map(|idx| ProjectiveVesta::msm_bigint(basis, &data[SRS_SIZE * idx..SRS_SIZE * (idx + 1)]))
        .collect::<Vec<_>>();
    let duration = now.elapsed();
    println!(
        "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!(" - Convert to affine coordinates");
    let now = std::time::Instant::now();
    let affine_committed_chunks = ProjectiveVesta::normalize_batch(committed_chunks.as_slice());
    let duration = now.elapsed();
    println!(
        "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("  - Combine the commitments");
    println!("    - Using a merkle commitment (poseidon hashing)");
    let now = std::time::Instant::now();
    let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );
    affine_committed_chunks.iter().for_each(|commitment| {
        fq_sponge.absorb_g(&[*commitment]);
    });
    let challenge = fq_sponge.squeeze(2);
    let duration = now.elapsed();
    println!(
        "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    for i in 0..2 {
        println!("");
        println!("- Storage protocol iteration {i}");
        println!("  - Computing randomizers for data chunks");
        let now = std::time::Instant::now();
        let powers = committed_chunks
            .iter()
            .scan(Fp::one(), |acc, _| {
                let res = *acc;
                *acc *= challenge;
                Some(res.into_bigint())
            })
            .collect::<Vec<_>>();
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Combining the data chunk commitments");
        let now = std::time::Instant::now();
        let final_commitment =
            ProjectiveVesta::msm_bigint(affine_committed_chunks.as_slice(), powers.as_slice())
                .into_affine();
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Convert data");
        println!("    - Temporary step until we have Montgomery representation preprocessing");
        let now = std::time::Instant::now();
        let mongomeryized_data = data
            .iter()
            .map(|x| Fp::from_bigint(*x).unwrap())
            .collect::<Vec<_>>();
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Combine randomized data chunks");
        let now = std::time::Instant::now();
        let final_chunk = (mongomeryized_data.len() / SRS_SIZE) - 1;
        let randomized_data = (0..SRS_SIZE)
            .into_par_iter()
            .map(|idx| {
                let mut acc = mongomeryized_data[final_chunk * SRS_SIZE + idx];
                (0..final_chunk).into_iter().rev().for_each(|chunk| {
                    acc *= challenge;
                    acc += mongomeryized_data[chunk * SRS_SIZE + idx];
                });
                acc
            })
            .collect::<Vec<_>>();
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Sample evaluation point");
        let now = std::time::Instant::now();
        let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
        fq_sponge.absorb_g(&[final_commitment]);
        let evaluation_point = fq_sponge.squeeze(2);
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Interpolate polynomial");
        println!("    - Fixed cost regardless of data size");
        let now = std::time::Instant::now();
        let randomized_data_poly =
            Evaluations::from_vec_and_domain(randomized_data, domain).interpolate();
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Evaluate polynomial and absorb evaluation");
        println!("    - Fixed cost regardless of data size");
        let now = std::time::Instant::now();
        let randomized_data_eval = randomized_data_poly.evaluate(&evaluation_point);
        let mut opening_proof_sponge =
            DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
                mina_poseidon::pasta::fq_kimchi::static_params(),
            );
        opening_proof_sponge.absorb_fr(&[randomized_data_eval]);
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("  - Opening proof");
        println!("    - Fixed cost regardless of data size");
        let now = std::time::Instant::now();
        let opening_proof = srs.open(
            &group_map,
            &[(
                DensePolynomialOrEvaluations::<_, Radix2EvaluationDomain<_>>::DensePolynomial(
                    &randomized_data_poly,
                ),
                PolyComm {
                    chunks: vec![Fp::zero()],
                },
            )],
            &[evaluation_point],
            Fp::one(), // Single polynomial, so we don't care
            Fp::one(), // Single polynomial, so we don't care
            opening_proof_sponge.clone(),
            rng,
        );
        let duration = now.elapsed();
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );

        println!("- Verifier protocol iteration {i}");
        println!("  - Verify opening proof");
        let now = std::time::Instant::now();
        let opening_proof_verifies = srs.verify(
            &group_map,
            &mut [BatchEvaluationProof {
                sponge: opening_proof_sponge.clone(),
                evaluation_points: vec![evaluation_point],
                polyscale: Fp::one(),
                evalscale: Fp::one(),
                evaluations: vec![Evaluation {
                    commitment: PolyComm {
                        chunks: vec![final_commitment],
                    },
                    evaluations: vec![vec![randomized_data_eval]],
                }],
                opening: &opening_proof,
                combined_inner_product: randomized_data_eval,
            }],
            rng,
        );
        let duration = now.elapsed();
        println!("    - Verifies: {}", opening_proof_verifies);
        println!(
            "    - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
            duration.as_secs(),
            duration.as_millis(),
            duration.as_micros(),
            duration.as_nanos(),
        );
    }

    ExitCode::SUCCESS
}

mod cli {
    use clap::{Parser, Subcommand};

    #[derive(Parser, Debug, Clone)]
    pub struct NetworkArgs {}

    #[derive(Parser, Debug, Clone)]
    pub struct StateProviderArgs {}

    #[derive(Parser, Debug, Clone)]
    pub struct ClientArgs {}

    #[derive(Parser, Debug, Clone)]
    pub struct PingArgs {}

    #[derive(Subcommand, Clone, Debug)]
    pub enum RequestCommands {
        #[command(name = "ping")]
        TestPreimageRead(PingArgs),
    }

    #[derive(Parser, Debug, Clone)]
    #[command(
        name = "mutable-state-demo",
        version = "0.1",
        about = "mutable-state-demo"
    )]
    pub enum Commands {
        #[command(name = "network")]
        Network(NetworkArgs),
        #[command(name = "state-provider")]
        StateProvider(StateProviderArgs),
        #[command(name = "client")]
        Client(ClientArgs),
        #[command(subcommand, name = "request")]
        Request(RequestCommands),
    }
}

pub fn main() -> ExitCode {
    use clap::Parser;
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Network(_args) => run_main(),
        cli::Commands::StateProvider(_args) => run_main(),
        cli::Commands::Client(_args) => run_main(),
        cli::Commands::Request(_subcommand) => run_main(),
    }
}
