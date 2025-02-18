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
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::process::ExitCode;

// To run:
// ```
// cargo run --release --bin mutable-state-demo
// ```

const SRS_SIZE: usize = 1 << 16;

pub struct VerifyContext {
    pub srs: SRS<Vesta>,
    pub group_map: <Vesta as CommitmentCurve>::Map,
}

impl VerifyContext {
    pub fn new() -> Self {
        let srs = SRS::<Vesta>::create(SRS_SIZE);
        let group_map = <Vesta as CommitmentCurve>::Map::setup();

        VerifyContext { srs, group_map }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Proof {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub evaluation_point: Fp,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub final_commitment: Vesta,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub randomized_data_eval: Fp,
    pub opening_proof: OpeningProof<Vesta>,
}

pub fn verify(context: &VerifyContext, proof: &Proof) -> bool {
    let VerifyContext { srs, group_map } = context;
    let Proof {
        evaluation_point,
        final_commitment,
        randomized_data_eval,
        opening_proof,
    } = proof;
    let rng = &mut rand::rngs::OsRng;
    let mut opening_proof_sponge =
        DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
    opening_proof_sponge.absorb_fr(&[*randomized_data_eval]);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![*evaluation_point],
            polyscale: Fp::one(),
            evalscale: Fp::one(),
            evaluations: vec![Evaluation {
                commitment: PolyComm {
                    chunks: vec![*final_commitment],
                },
                evaluations: vec![vec![*randomized_data_eval]],
            }],
            opening: opening_proof,
            combined_inner_product: *randomized_data_eval,
        }],
        rng,
    )
}

pub fn run_profiling_demo() -> ExitCode {
    println!("Startup time (cacheable, 1-time cost)");

    println!("- Generate SRS and group map");
    let now = std::time::Instant::now();
    let verify_context = VerifyContext::new();
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    let VerifyContext { srs, group_map } = &verify_context;

    println!("- Generate SRS lagrange basis");
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
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

        let proof = Proof {
            evaluation_point,
            final_commitment,
            randomized_data_eval,
            opening_proof,
        };

        println!("- Verifier protocol iteration {i}");
        println!("  - Verify opening proof");
        let now = std::time::Instant::now();
        let opening_proof_verifies = verify(&verify_context, &proof);
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

pub mod network {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {}
    }

    use serde::{Deserialize, Serialize};
    use std::net::TcpListener;
    use std::process::ExitCode;

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
    }

    pub fn main(_arg: cli::Args) -> ExitCode {
        println!("I'm a network!");

        let address = "127.0.0.1:3088";

        let listener = TcpListener::bind(address).unwrap();
        for stream in listener.incoming() {
            let mut deserializer = rmp_serde::Deserializer::new(stream.unwrap());
            let message = Message::deserialize(&mut deserializer).unwrap();
            match message {
                Message::StringMessage(i) => println!("stream got data: {}", i),
            }
        }

        ExitCode::SUCCESS
    }
}

pub mod state_provider {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {}
    }

    use super::network::Message as NetworkMessage;
    use serde::{Deserialize, Serialize};
    use std::net::{TcpListener, TcpStream};
    use std::process::ExitCode;
    use std::sync::mpsc;
    use std::thread;

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        RunDemo,
    }

    enum Event {
        SendNumber(u8),
        HandleStreamMessage(Message),
    }

    pub fn main(_arg: cli::Args) -> ExitCode {
        println!("I'm a state provider!");

        let (event_queue_sender, event_queue_receiver) = mpsc::channel();

        let address = "127.0.0.1:3089";

        let event_queue_stream_sender = event_queue_sender.clone();

        thread::spawn(move || {
            let listener = TcpListener::bind(address).unwrap();
            for stream in listener.incoming() {
                let mut deserializer = rmp_serde::Deserializer::new(stream.unwrap());
                let message = Message::deserialize(&mut deserializer).unwrap();
                event_queue_stream_sender
                    .send(Event::HandleStreamMessage(message))
                    .unwrap();
            }
        });

        let network_address = "127.0.0.1:3088";

        for i in 0..10 {
            event_queue_sender.send(Event::SendNumber(i)).unwrap();
        }

        for event in event_queue_receiver.into_iter() {
            let mut serializer =
                rmp_serde::Serializer::new(TcpStream::connect(network_address).unwrap());

            match event {
                Event::SendNumber(i) => {
                    let data = format!("{}", i);
                    println!("sending data {}", data);

                    NetworkMessage::StringMessage(data)
                        .serialize(&mut serializer)
                        .unwrap();
                }
                Event::HandleStreamMessage(message) => match message {
                    Message::StringMessage(data) => {
                        println!("forwarding data {}", data);
                        NetworkMessage::StringMessage(data)
                            .serialize(&mut serializer)
                            .unwrap();
                    }
                    Message::RunDemo => {
                        super::run_profiling_demo();
                    }
                },
            }
        }

        ExitCode::SUCCESS
    }
}

pub mod client {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {}
    }

    use super::{
        network::Message as NetworkMessage, state_provider::Message as StateProviderMessage,
    };
    use serde::Serialize;
    use std::net::TcpStream;
    use std::process::ExitCode;

    pub fn main(_arg: cli::Args) -> ExitCode {
        println!("I'm a client!");

        let network_address = "127.0.0.1:3088";
        let storage_provider_address = "127.0.0.1:3089";

        for i in 0..10 {
            let mut serializer =
                rmp_serde::Serializer::new(TcpStream::connect(network_address).unwrap());
            let data = format!("client {}", i);
            println!("sending data {}", data);
            NetworkMessage::StringMessage(data)
                .serialize(&mut serializer)
                .unwrap();
        }

        for i in 0..30 {
            let mut serializer =
                rmp_serde::Serializer::new(TcpStream::connect(storage_provider_address).unwrap());
            let data = format!("client {}", i);
            println!("sending data {}", data);
            StateProviderMessage::StringMessage(data)
                .serialize(&mut serializer)
                .unwrap();
        }

        let mut serializer =
            rmp_serde::Serializer::new(TcpStream::connect(storage_provider_address).unwrap());
        println!("Requesting demo run");
        StateProviderMessage::RunDemo
            .serialize(&mut serializer)
            .unwrap();

        ExitCode::SUCCESS
    }
}

pub mod request {
    pub mod cli {
        use clap::{Parser, Subcommand};

        #[derive(Parser, Debug, Clone)]
        pub struct DemoArgs {}

        #[derive(Subcommand, Clone, Debug)]
        pub enum Command {
            #[command(name = "demo")]
            Demo(DemoArgs),
        }
    }

    use std::process::ExitCode;

    pub fn main(sub_command: cli::Command) -> ExitCode {
        match sub_command {
            cli::Command::Demo(_args) => super::run_profiling_demo(),
        }
    }
}

pub mod cli {
    use super::{client, network, request, state_provider};
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    #[command(
        name = "mutable-state-demo",
        version = "0.1",
        about = "mutable-state-demo"
    )]
    pub enum Command {
        #[command(name = "network")]
        Network(network::cli::Args),
        #[command(name = "state-provider")]
        StateProvider(state_provider::cli::Args),
        #[command(name = "client")]
        Client(client::cli::Args),
        #[command(subcommand, name = "request")]
        Request(request::cli::Command),
    }
}

pub fn main() -> ExitCode {
    use clap::Parser;
    let args = cli::Command::parse();
    match args {
        cli::Command::Network(args) => network::main(args),
        cli::Command::StateProvider(args) => state_provider::main(args),
        cli::Command::Client(args) => client::main(args),
        cli::Command::Request(subcommand) => request::main(subcommand),
    }
}
