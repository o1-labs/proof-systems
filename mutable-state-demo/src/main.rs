use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
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
// * open a new terminal window, start the network daemon
// ```
// cargo run --release --bin mutable-state-demo -- network
// ```
// * open a new terminal window, start the state provider daemon
// ```
// cargo run --release --bin mutable-state-demo -- network
// ```
// * open a new terminal window, run the client
// ```
// cargo run --release --bin mutable-state-demo -- client
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

pub struct ProverInputs<'a> {
    pub challenge: Fp,
    pub data: &'a mut [Fp],
    pub affine_committed_chunks: Vec<Vesta>,
}

impl<'a> ProverInputs<'a> {
    pub fn from_data(context: &VerifyContext, data: &'a mut [Fp]) -> Self {
        let VerifyContext { srs, group_map: _ } = context;

        // TODO: Cache this somewhere
        let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();

        let basis = srs
            .get_lagrange_basis(domain)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();
        let basis = basis.as_slice();
        let committed_chunks = (0..data.len() / SRS_SIZE)
            .into_par_iter()
            .map(|idx| {
                ProjectiveVesta::msm(basis, &data[SRS_SIZE * idx..SRS_SIZE * (idx + 1)]).unwrap()
            })
            .collect::<Vec<_>>();

        let affine_committed_chunks = ProjectiveVesta::normalize_batch(committed_chunks.as_slice());

        let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
        affine_committed_chunks.iter().for_each(|commitment| {
            fq_sponge.absorb_g(&[*commitment]);
        });
        let challenge = fq_sponge.squeeze(2);

        ProverInputs {
            challenge,
            data,
            affine_committed_chunks,
        }
    }
}

fn prove(context: &VerifyContext, inputs: &ProverInputs) -> Proof {
    let VerifyContext { srs, group_map } = context;
    let rng = &mut rand::rngs::OsRng;
    let ProverInputs {
        challenge,
        data,
        affine_committed_chunks,
    } = inputs;

    let powers = affine_committed_chunks
        .iter()
        .scan(Fp::one(), |acc, _| {
            let res = *acc;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    let final_commitment =
        ProjectiveVesta::msm_bigint(affine_committed_chunks.as_slice(), powers.as_slice())
            .into_affine();

    let final_chunk = (data.len() / SRS_SIZE) - 1;
    let randomized_data = (0..SRS_SIZE)
        .into_par_iter()
        .map(|idx| {
            let mut acc = data[final_chunk * SRS_SIZE + idx];
            (0..final_chunk).into_iter().rev().for_each(|chunk| {
                acc *= challenge;
                acc += data[chunk * SRS_SIZE + idx];
            });
            acc
        })
        .collect::<Vec<_>>();

    let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );
    fq_sponge.absorb_g(&[final_commitment]);
    let evaluation_point = fq_sponge.squeeze(2);

    // TODO: Cache this somewhere
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();

    let randomized_data_poly =
        Evaluations::from_vec_and_domain(randomized_data, domain).interpolate();

    let randomized_data_eval = randomized_data_poly.evaluate(&evaluation_point);
    let mut opening_proof_sponge =
        DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
    opening_proof_sponge.absorb_fr(&[randomized_data_eval]);

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

    Proof {
        evaluation_point,
        final_commitment,
        randomized_data_eval,
        opening_proof,
    }
}

pub mod network {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {}
    }

    use super::{Proof, VerifyContext};
    use serde::{Deserialize, Serialize};
    use std::net::TcpListener;
    use std::process::ExitCode;

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        VerifyProof(Proof),
    }

    pub fn main(_arg: cli::Args) -> ExitCode {
        println!("I'm a network!");

        let verify_context = VerifyContext::new();

        println!("Set up verify context");

        let address = "127.0.0.1:3088";

        let listener = TcpListener::bind(address).unwrap();
        for stream in listener.incoming() {
            let mut deserializer = rmp_serde::Deserializer::new(stream.unwrap());
            let message = Message::deserialize(&mut deserializer).unwrap();
            match message {
                Message::StringMessage(i) => println!("stream got data: {}", i),
                Message::VerifyProof(proof) => {
                    println!("Verifying proof");
                    let now = std::time::Instant::now();
                    let valid = super::verify(&verify_context, &proof);
                    let duration = now.elapsed();
                    println!("proof verifies? {}", valid);
                    println!(
                        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                        duration.as_secs(),
                        duration.as_millis(),
                        duration.as_micros(),
                        duration.as_nanos(),
                    );
                }
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

    use super::{network::Message as NetworkMessage, prove, ProverInputs, VerifyContext};
    use mina_curves::pasta::Fp;
    use serde::{Deserialize, Serialize};
    use std::net::{TcpListener, TcpStream};
    use std::process::ExitCode;
    use std::sync::mpsc;
    use std::thread;

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        StateRetentionProof,
        UpdateProverInputs(usize),
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

        for i in 0..2 {
            event_queue_sender.send(Event::SendNumber(i)).unwrap();
        }

        println!("Setting up initial prover inputs");

        let verify_context = VerifyContext::new();

        // TODO: mmap data
        let mut data: Vec<_> = (0..1 << 20).map(|i| Fp::from(i)).collect();
        let mut prover_inputs = ProverInputs::from_data(&verify_context, &mut data);

        for event in event_queue_receiver.into_iter() {
            let network_serializer =
                || rmp_serde::Serializer::new(TcpStream::connect(network_address).unwrap());

            match event {
                Event::SendNumber(i) => {
                    let mut serializer = network_serializer();
                    let data = format!("{}", i);
                    println!("sending data {}", data);

                    NetworkMessage::StringMessage(data)
                        .serialize(&mut serializer)
                        .unwrap();
                }
                Event::HandleStreamMessage(message) => match message {
                    Message::StringMessage(data) => {
                        let mut serializer = network_serializer();
                        println!("forwarding data {}", data);
                        NetworkMessage::StringMessage(data)
                            .serialize(&mut serializer)
                            .unwrap();
                    }
                    Message::StateRetentionProof => {
                        println!("Creating storage proof");
                        let now = std::time::Instant::now();
                        let proof = prove(&verify_context, &prover_inputs);
                        let duration = now.elapsed();
                        println!(
                            "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                            duration.as_secs(),
                            duration.as_millis(),
                            duration.as_micros(),
                            duration.as_nanos(),
                        );
                        let mut serializer = network_serializer();
                        NetworkMessage::VerifyProof(proof)
                            .serialize(&mut serializer)
                            .unwrap();
                    }
                    Message::UpdateProverInputs(i) => {
                        println!("Updating prover inputs from scratch");
                        let now = std::time::Instant::now();
                        // WARNING: Changing the length of data is incredibly unsafe if we don't
                        // also immediately update prover_inputs!
                        // This shouldn't happen in production, at least.
                        data = (0..1 << i).map(|i| Fp::from(i)).collect();
                        prover_inputs = ProverInputs::from_data(&verify_context, &mut data);
                        let duration = now.elapsed();
                        println!(
                            "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                            duration.as_secs(),
                            duration.as_millis(),
                            duration.as_micros(),
                            duration.as_nanos(),
                        );
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
        let state_provider_address = "127.0.0.1:3089";

        let network_serializer =
            || rmp_serde::Serializer::new(TcpStream::connect(network_address).unwrap());

        let state_provider_serializer =
            || rmp_serde::Serializer::new(TcpStream::connect(state_provider_address).unwrap());

        for i in 0..2 {
            let mut serializer = network_serializer();

            let data = format!("client {}", i);
            println!("sending data {}", data);
            NetworkMessage::StringMessage(data)
                .serialize(&mut serializer)
                .unwrap();
        }

        for i in 0..3 {
            let mut serializer = state_provider_serializer();
            let data = format!("client {}", i);
            println!("sending data {}", data);
            StateProviderMessage::StringMessage(data)
                .serialize(&mut serializer)
                .unwrap();
        }

        let mut serializer = state_provider_serializer();
        println!("Requesting state proof");
        StateProviderMessage::StateRetentionProof
            .serialize(&mut serializer)
            .unwrap();

        let mut serializer = state_provider_serializer();
        println!("Requesting state proof");
        StateProviderMessage::StateRetentionProof
            .serialize(&mut serializer)
            .unwrap();

        let mut serializer = state_provider_serializer();
        println!("Requesting data of size 2^18");
        StateProviderMessage::UpdateProverInputs(18)
            .serialize(&mut serializer)
            .unwrap();

        let mut serializer = state_provider_serializer();
        println!("Requesting state proof");
        StateProviderMessage::StateRetentionProof
            .serialize(&mut serializer)
            .unwrap();

        let mut serializer = state_provider_serializer();
        println!("Requesting state proof");
        StateProviderMessage::StateRetentionProof
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
            cli::Command::Demo(_args) => todo!("Deleted, add some proper commands here"),
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
