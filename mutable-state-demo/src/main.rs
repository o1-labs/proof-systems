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
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
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
                    + srs.h
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

    let mut blinder_sum = Fp::zero();

    let powers = affine_committed_chunks
        .iter()
        .scan(Fp::one(), |acc, _| {
            let res = *acc;
            blinder_sum += res;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    let final_commitment =
        ProjectiveVesta::msm_bigint(affine_committed_chunks.as_slice(), powers.as_slice())
            .into_affine();

    let final_chunk = (data.len() / SRS_SIZE) - 1;
    let randomized_data = {
        let mut initial: Vec<_> = data[final_chunk * SRS_SIZE..(final_chunk + 1) * SRS_SIZE]
            .iter()
            .cloned()
            .collect();
        (0..final_chunk).into_iter().rev().for_each(|chunk| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= challenge;
                *acc += data[chunk * SRS_SIZE + idx];
            });
        });
        initial
    };

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
                chunks: vec![blinder_sum],
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

pub fn stream_read<'a, T: serde::Deserialize<'a>>(
    stream: std::net::TcpStream,
) -> (std::net::TcpStream, T) {
    let mut deserializer = rmp_serde::Deserializer::new(stream);
    let msg = T::deserialize(&mut deserializer).unwrap();
    let stream = deserializer.into_inner();
    (stream, msg)
}

pub fn stream_write<'a, T: serde::Serialize>(
    stream: std::net::TcpStream,
    response: T,
) -> std::net::TcpStream {
    let mut serializer = rmp_serde::Serializer::new(stream);
    response.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

pub fn rpc<'a, A: std::net::ToSocketAddrs, T: serde::Serialize, U: serde::Deserialize<'a>>(
    address: A,
    msg: T,
) -> U {
    let stream = std::net::TcpStream::connect(address).unwrap();
    let stream = stream_write(stream, msg);
    let (_stream, response) = stream_read(stream);
    response
}

pub fn rpc_unit<'a, A: std::net::ToSocketAddrs, T: serde::Serialize>(address: A, msg: T) {
    rpc::<'a, A, T, ()>(address, msg)
}

pub fn rpc_handle<'a, T: serde::Deserialize<'a>, U: serde::Serialize, F: FnOnce(T) -> U>(
    stream: std::net::TcpStream,
    f: F,
) {
    let (stream, msg) = stream_read(stream);
    let response = f(msg);
    stream_write(stream, response);
}

pub mod network {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {
            #[arg(
                short = 'a',
                long,
                value_name = "ADDRESS",
                help = "Address to bind to",
                default_value = "127.0.0.1:3088"
            )]
            pub address: String,
        }
    }

    use super::{Proof, VerifyContext};
    use mina_curves::pasta::Vesta;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::net::TcpListener;
    use std::process::ExitCode;

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct ReadIntent {
        pub region: u64,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub query_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct ReadResponse {
        pub region: u64,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub query_commitment: Vesta,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub response_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct WriteIntent {
        pub region: u64,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub query_commitment: Vesta,
        #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
        pub precondition_commitment: Option<Vesta>,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub data_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub enum WriteResult {
        Success {
            region: u64,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            query_commitment: Vesta,
            #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
            precondition_commitment: Option<Vesta>,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            old_data_commitment: Vesta,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            data_commitment: Vesta,
        },
        Failure {
            region: u64,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            query_commitment: Vesta,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            precondition_commitment: Vesta,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            data_commitment: Vesta,
        },
    }

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        VerifyProof(Proof),
        ReadIntent(ReadIntent),
        ReadResponse(ReadResponse),
        WriteIntent(WriteIntent),
        WriteResult(WriteResult),
    }

    pub fn main(arg: cli::Args) -> ExitCode {
        println!("I'm a network!");

        let cli::Args { address } = arg;

        let verify_context = VerifyContext::new();

        println!("Set up verify context");

        let listener = TcpListener::bind(address).unwrap();
        for stream in listener.incoming() {
            super::rpc_handle(stream.unwrap(), |message| match message {
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
                Message::ReadIntent(ReadIntent {
                    region,
                    query_commitment,
                }) => {
                    println!("Saw read intent for {region}:\n{:?}", query_commitment);
                }
                Message::ReadResponse(ReadResponse {
                    region,
                    query_commitment,
                    response_commitment,
                }) => {
                    println!(
                        "Saw read response for {region}:\n{:?}\n{:?}",
                        query_commitment, response_commitment
                    );
                }
                Message::WriteIntent(WriteIntent {
                    region,
                    query_commitment,
                    precondition_commitment,
                    data_commitment,
                }) => {
                    println!(
                        "Saw read write for {region}:\n{:?}\n{:?}\n{:?}",
                        query_commitment, precondition_commitment, data_commitment
                    );
                }
                Message::WriteResult(WriteResult::Success {
                    region,
                    query_commitment,
                    precondition_commitment,
                    data_commitment,
                    old_data_commitment,
                }) => {
                    println!(
                        "Saw read response for {region}:\n{:?}\n{:?}\n{:?}\n{:?}",
                        query_commitment,
                        precondition_commitment,
                        data_commitment,
                        old_data_commitment,
                    );
                }
                Message::WriteResult(WriteResult::Failure {
                    region,
                    query_commitment,
                    precondition_commitment,
                    data_commitment,
                }) => {
                    println!(
                        "Saw read response for {region}:\n{:?}\n{:?}\n{:?}",
                        query_commitment, precondition_commitment, data_commitment,
                    );
                }
            });
        }

        ExitCode::SUCCESS
    }
}

pub mod state_provider {
    pub mod cli {
        use clap::Parser;

        #[derive(Parser, Debug, Clone)]
        pub struct Args {
            #[arg(
                short = 'a',
                long,
                value_name = "ADDRESS",
                help = "Address to bind to",
                default_value = "127.0.0.1:3089"
            )]
            pub address: String,
            #[arg(
                short = 'n',
                long,
                value_name = "NETWORK_ADDRESS",
                help = "Address of the network node",
                default_value = "127.0.0.1:3088"
            )]
            pub network_address: String,
            #[arg(
                short = 'f',
                long,
                value_name = "FILENAME",
                help = "File to use as storage"
            )]
            pub mmap_file: Option<String>,
        }
    }

    use super::{network, prove, ProverInputs, VerifyContext, SRS_SIZE};
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use mina_curves::pasta::{Fp, ProjectiveVesta, Vesta};
    use poly_commitment::SRS;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::fs::{File, OpenOptions};
    use std::net::{TcpListener, TcpStream};
    use std::process::ExitCode;
    use std::sync::mpsc;
    use std::thread;

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct ReadQuery {
        pub region: u64,
        pub addresses: Vec<u64>,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub query_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct ReadResponse {
        #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
        pub values: Vec<Fp>,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub response_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct WriteQuery {
        pub region: u64,
        pub addresses: Vec<u64>,
        #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
        pub values: Vec<Fp>,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub query_commitment: Vesta,
        #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
        pub precondition_commitment: Option<Vesta>,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pub data_commitment: Vesta,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub enum WriteResponse {
        Success,
        Failed {
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            old_data_commitment: Vesta,
        },
    }

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        StateRetentionProof,
        UpdateProverInputs,
        Read(ReadQuery),
        Write(WriteQuery),
    }

    enum Event {
        SendNumber(u8),
        HandleStreamMessage(TcpStream, Message),
    }

    enum DataSource {
        Data(Vec<Fp>),
        Mmap { _file: File, mmap: memmap::MmapMut },
    }

    pub fn main(arg: cli::Args) -> ExitCode {
        println!("I'm a state provider!");

        let cli::Args {
            network_address,
            address,
            mmap_file,
        } = arg;

        let (event_queue_sender, event_queue_receiver) = mpsc::channel();

        let event_queue_stream_sender = event_queue_sender.clone();

        thread::spawn(move || {
            let listener = TcpListener::bind(address).unwrap();
            for stream in listener.incoming() {
                let (stream, message) = super::stream_read(stream.unwrap());
                event_queue_stream_sender
                    .send(Event::HandleStreamMessage(stream, message))
                    .unwrap();
            }
        });

        for i in 0..2 {
            event_queue_sender.send(Event::SendNumber(i)).unwrap();
        }

        println!("Setting up initial prover inputs");

        let verify_context = VerifyContext::new();
        let VerifyContext { srs, group_map: _ } = &verify_context;
        let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
        let basis = srs
            .get_lagrange_basis(domain)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();
        let basis = basis.as_slice();

        let mut data_source = match mmap_file {
            None => DataSource::Data((0..1 << 20).map(|i| Fp::from(i)).collect()),
            Some(mmap_file) => {
                let file = {
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(mmap_file)
                        .unwrap()
                };
                let mmap = { unsafe { memmap::MmapMut::map_mut(&file).unwrap() } };
                DataSource::Mmap { _file: file, mmap }
            }
        };

        let data = {
            match &mut data_source {
                DataSource::Data(v) => v.as_mut_slice(),
                DataSource::Mmap { _file: _, mmap } => {
                    let mmap_data = mmap.as_mut();
                    let (prefix, mmap_data, suffix) = unsafe { mmap_data.align_to_mut::<Fp>() };
                    if prefix.len() != 0 || suffix.len() != 0 {
                        panic!(
                        "Expected zero lengths of rejected space around mmapped file, but got prefix={} and suffix={}",
                        prefix.len(),
                        suffix.len()
                    );
                    }
                    let num_regions = mmap_data.len() / SRS_SIZE;
                    if num_regions * SRS_SIZE != mmap_data.len() {
                        panic!(
                            "Expected file size to be a multiple of {} bytes",
                            std::mem::size_of::<Fp>() * SRS_SIZE
                        );
                    }
                    mmap_data
                }
            }
        };

        println!("number of field elements: {}", data.len());

        for i in 0..data.len() {
            data[i] = Fp::from(0u64);
        }
        let mut prover_inputs = ProverInputs::from_data(&verify_context, data);

        for event in event_queue_receiver.into_iter() {
            match event {
                Event::SendNumber(i) => {
                    let data = format!("{}", i);
                    println!("sending data {}", data);

                    super::rpc(
                        network_address.clone(),
                        network::Message::StringMessage(data),
                    )
                }
                Event::HandleStreamMessage(stream, message) => match message {
                    Message::StringMessage(data) => {
                        println!("forwarding data {}", data);
                        super::rpc_unit(
                            network_address.clone(),
                            network::Message::StringMessage(data),
                        );
                        super::stream_write(stream, ());
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
                        super::rpc_unit(
                            network_address.clone(),
                            network::Message::VerifyProof(proof),
                        );
                        super::stream_write(stream, ());
                    }
                    Message::UpdateProverInputs => {
                        println!("Updating prover inputs from scratch");
                        let now = std::time::Instant::now();
                        prover_inputs = ProverInputs::from_data(&verify_context, data);
                        let duration = now.elapsed();
                        println!(
                            "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                            duration.as_secs(),
                            duration.as_millis(),
                            duration.as_micros(),
                            duration.as_nanos(),
                        );
                        super::stream_write(stream, ());
                    }
                    Message::Read(ReadQuery {
                        region,
                        addresses,
                        query_commitment,
                    }) => {
                        let is_sorted = (0..addresses.len() - 1)
                            .map(|idx| addresses[idx] < addresses[idx + 1])
                            .reduce(|x, y| x && y)
                            .unwrap_or(true);
                        if !is_sorted {
                            super::stream_write(stream, Err::<ReadResponse, ()>(()));
                            continue;
                        }
                        let address_basis: Vec<_> = addresses
                            .par_iter()
                            .map(|idx| basis[*idx as usize])
                            .collect();
                        let computed_commitment = {
                            address_basis
                                .par_iter()
                                .map(|x| x.into_group())
                                .reduce(|| Vesta::zero().into_group(), |x, y| x + y)
                                + srs.h
                        }
                        .into_affine();
                        let (response, broadcast) = if query_commitment != computed_commitment {
                            (Err(()), None)
                        } else {
                            let values: Vec<_> = addresses
                                .into_iter()
                                .map(|idx| {
                                    prover_inputs.data[region as usize * SRS_SIZE + idx as usize]
                                })
                                .collect();
                            let response_commitment = {
                                ProjectiveVesta::msm(address_basis.as_slice(), values.as_slice())
                                    .unwrap()
                                    + srs.h
                            }
                            .into_affine();
                            (
                                Ok(ReadResponse {
                                    values,
                                    response_commitment,
                                }),
                                Some(network::Message::ReadResponse(network::ReadResponse {
                                    region,
                                    query_commitment,
                                    response_commitment,
                                })),
                            )
                        };
                        super::stream_write(stream, response);
                        if let Some(broadcast) = broadcast {
                            super::rpc_unit(network_address.clone(), broadcast);
                        }
                    }
                    Message::Write(WriteQuery {
                        region,
                        addresses,
                        values,
                        query_commitment,
                        precondition_commitment,
                        data_commitment,
                    }) => {
                        let is_sorted = (0..addresses.len() - 1)
                            .map(|idx| addresses[idx] < addresses[idx + 1])
                            .reduce(|x, y| x && y)
                            .unwrap_or(true);
                        if !is_sorted {
                            super::stream_write(stream, Err::<ReadResponse, ()>(()));
                            continue;
                        }
                        let address_basis: Vec<_> = addresses
                            .par_iter()
                            .map(|idx| basis[*idx as usize])
                            .collect();
                        let computed_query_commitment = {
                            address_basis
                                .par_iter()
                                .map(|x| x.into_group())
                                .reduce(|| Vesta::zero().into_group(), |x, y| x + y)
                                + srs.h
                        }
                        .into_affine();
                        let respond =
                            |msg: Result<WriteResponse, ()>| super::stream_write(stream, msg);
                        if addresses.len() != values.len() {
                            respond(Err(()));
                            continue;
                        }
                        if query_commitment != computed_query_commitment {
                            respond(Err(()));
                            continue;
                        }
                        let computed_data_commitment = {
                            ProjectiveVesta::msm(address_basis.as_slice(), values.as_slice())
                                .unwrap()
                                + srs.h
                        }
                        .into_affine();
                        if data_commitment != computed_data_commitment {
                            respond(Err(()));
                            continue;
                        }
                        let old_values: Vec<_> = addresses
                            .iter()
                            .map(|idx| {
                                prover_inputs.data[region as usize * SRS_SIZE + *idx as usize]
                            })
                            .collect();
                        let old_data_commitment = {
                            ProjectiveVesta::msm(address_basis.as_slice(), old_values.as_slice())
                                .unwrap()
                                + srs.h
                        }
                        .into_affine();
                        if precondition_commitment.is_some()
                            && precondition_commitment.unwrap() != old_data_commitment
                        {
                            respond(Ok(WriteResponse::Failed {
                                old_data_commitment,
                            }));
                            super::rpc_unit(
                                network_address.clone(),
                                network::Message::WriteResult(network::WriteResult::Failure {
                                    region,
                                    query_commitment,
                                    precondition_commitment: precondition_commitment.unwrap(),
                                    data_commitment,
                                }),
                            );
                            continue;
                        }
                        respond(Ok(WriteResponse::Success));
                        super::rpc_unit(
                            network_address.clone(),
                            network::Message::WriteResult(network::WriteResult::Success {
                                region,
                                query_commitment,
                                precondition_commitment,
                                data_commitment,
                                old_data_commitment,
                            }),
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
        pub struct Args {
            #[arg(
                short = 'a',
                long,
                value_name = "ADDRESS",
                help = "Address to bind to",
                default_value = "127.0.0.1:3090"
            )]
            pub address: String,
            #[arg(
                short = 's',
                long,
                value_name = "ADDRESS",
                help = "Address to bind to",
                default_value = "127.0.0.1:3089"
            )]
            pub state_provider_address: String,
            #[arg(
                short = 'n',
                long,
                value_name = "NETWORK_ADDRESS",
                help = "Address of the network node",
                default_value = "127.0.0.1:3088"
            )]
            pub network_address: String,
        }
    }

    use super::{network, state_provider, VerifyContext, SRS_SIZE};
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use mina_curves::pasta::{Fp, ProjectiveVesta, Vesta};
    use poly_commitment::SRS;
    use rayon::{iter::ParallelIterator, prelude::IntoParallelRefIterator};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::net::TcpListener;
    use std::process::ExitCode;

    #[derive(Serialize, Deserialize)]
    pub struct ReadQuery {
        pub region: u64,
        pub addresses: Vec<u64>,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct ReadResponse {
        #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
        pub values: Vec<Fp>,
    }

    #[derive(Serialize, Deserialize)]
    pub enum Message {
        NetworkStringMessage(String),
        StateProviderStringMessage(String),
        StateRetentionProof,
        UpdateProverInputs,
        Read(ReadQuery),
        Quit,
    }

    pub fn main(arg: cli::Args) -> ExitCode {
        println!("I'm a client!");

        let cli::Args {
            state_provider_address,
            network_address,
            address,
        } = arg;

        let VerifyContext { srs, group_map: _ } = VerifyContext::new();
        let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
        let basis = srs
            .get_lagrange_basis(domain)
            .iter()
            .map(|x| x.chunks[0])
            .collect::<Vec<_>>();
        let basis = basis.as_slice();

        let listener = TcpListener::bind(address).unwrap();
        for stream in listener.incoming() {
            let (stream, message) = super::stream_read(stream.unwrap());
            match message {
                Message::NetworkStringMessage(s) => {
                    super::stream_write(stream, ());
                    super::rpc_unit(network_address.clone(), network::Message::StringMessage(s));
                }
                Message::StateProviderStringMessage(s) => {
                    super::stream_write(stream, ());
                    super::rpc_unit(
                        state_provider_address.clone(),
                        state_provider::Message::StringMessage(s),
                    );
                }
                Message::StateRetentionProof => {
                    super::rpc_unit(
                        state_provider_address.clone(),
                        state_provider::Message::StateRetentionProof,
                    );
                    super::stream_write(stream, ());
                }
                Message::UpdateProverInputs => {
                    super::rpc_unit(
                        state_provider_address.clone(),
                        state_provider::Message::UpdateProverInputs,
                    );
                    super::stream_write(stream, ());
                }
                Message::Read(ReadQuery { region, addresses }) => {
                    let address_basis: Vec<_> = addresses
                        .par_iter()
                        .map(|idx| basis[*idx as usize])
                        .collect();
                    let query_commitment = {
                        address_basis
                            .par_iter()
                            .map(|x| x.into_group())
                            .reduce(|| Vesta::zero().into_group(), |x, y| x + y)
                            + srs.h
                    }
                    .into_affine();
                    super::rpc_unit(
                        network_address.clone(),
                        network::Message::ReadIntent(network::ReadIntent {
                            region,
                            query_commitment,
                        }),
                    );
                    if let Ok(state_provider::ReadResponse {
                        values,
                        response_commitment,
                    }) = super::rpc::<_, _, Result<state_provider::ReadResponse, ()>>(
                        state_provider_address.clone(),
                        state_provider::Message::Read(state_provider::ReadQuery {
                            region,
                            addresses,
                            query_commitment,
                        }),
                    ) {
                        let computed_response_commitment = {
                            ProjectiveVesta::msm(address_basis.as_slice(), values.as_slice())
                                .unwrap()
                                + srs.h
                        }
                        .into_affine();
                        assert_eq!(response_commitment, computed_response_commitment);
                        super::stream_write(stream, ReadResponse { values });
                    }
                }
                Message::Quit => {
                    super::stream_write(stream, ());
                    break;
                }
            };
        }

        ExitCode::SUCCESS
    }
}

pub mod request {
    pub mod cli {
        use clap::{Parser, Subcommand};

        #[derive(Parser, Debug, Clone)]
        pub struct Args {
            #[arg(
                short = 'c',
                long,
                value_name = "ADDRESS",
                help = "Client address to connect to",
                default_value = "127.0.0.1:3090"
            )]
            pub client_address: String,
        }

        #[derive(Subcommand, Clone, Debug)]
        pub enum Command {
            #[command(name = "network-messages")]
            NetworkStringMessages(Args),
            #[command(name = "state-provider-message")]
            StateProviderStringMessage(Args),
            #[command(name = "state-retention-proof")]
            StateRetentionProof(Args),
            #[command(name = "update-inputs")]
            UpdateProverInputs(Args),
            #[command(name = "read")]
            Read(Args),
            #[command(name = "quit")]
            Quit(Args),
        }
    }

    use super::client::{Message as ClientMessage, ReadQuery, ReadResponse};
    use serde::{Deserialize, Serialize};
    use std::io::Read;
    use std::process::ExitCode;

    pub fn main(sub_command: cli::Command) -> ExitCode {
        match sub_command {
            cli::Command::NetworkStringMessages(args) => {
                let cli::Args { client_address } = args;
                loop {
                    let mut input = String::new();
                    match std::io::stdin().read_line(&mut input) {
                        Ok(_) => super::rpc_unit(
                            client_address.clone(),
                            ClientMessage::NetworkStringMessage(input),
                        ),
                        Err(_) => break,
                    }
                }
                ExitCode::SUCCESS
            }
            cli::Command::StateProviderStringMessage(args) => {
                let cli::Args { client_address } = args;
                let mut input = String::new();
                if let Ok(_) = std::io::stdin().read_to_string(&mut input) {
                    super::rpc_unit(
                        client_address,
                        ClientMessage::StateProviderStringMessage(input),
                    );
                }
                ExitCode::SUCCESS
            }
            cli::Command::StateRetentionProof(args) => {
                let cli::Args { client_address } = args;
                super::rpc_unit(client_address, ClientMessage::StateRetentionProof);
                ExitCode::SUCCESS
            }
            cli::Command::UpdateProverInputs(args) => {
                let cli::Args { client_address } = args;
                super::rpc_unit(client_address, ClientMessage::UpdateProverInputs);
                ExitCode::SUCCESS
            }
            cli::Command::Read(args) => {
                let cli::Args { client_address } = args;
                let query = {
                    let reader = serde_json::de::IoRead::new(std::io::stdin());
                    let mut deserializer = serde_json::Deserializer::new(reader);
                    ReadQuery::deserialize(&mut deserializer).unwrap()
                };
                let response: ReadResponse = super::rpc(client_address, ClientMessage::Read(query));
                {
                    let mut serializer = serde_json::Serializer::new(std::io::stdout());
                    response.serialize(&mut serializer).unwrap();
                }
                ExitCode::SUCCESS
            }
            cli::Command::Quit(args) => {
                let cli::Args { client_address } = args;
                super::rpc_unit(client_address, ClientMessage::Quit);
                ExitCode::SUCCESS
            }
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
