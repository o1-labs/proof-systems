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

pub mod merkle_tree {
    use ark_ff::Zero;
    use kimchi::plonk_sponge::FrSponge as _;
    use mina_curves::pasta::Fp;
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFrSponge};

    // TODO: Make opaque
    pub struct MerkleTree {
        pub leaf_hashes: Vec<Fp>,
        pub tree_hashes: Vec<Fp>, // Internal nodes only — no direct leaf hashes
    }

    impl MerkleTree {
        pub fn hash(left: Fp, right: Fp) -> Fp {
            let mut sponge = DefaultFrSponge::<Fp, PlonkSpongeConstantsKimchi>::new(
                mina_poseidon::pasta::fp_kimchi::static_params(),
            );
            sponge.absorb(&left);
            sponge.absorb(&right);
            sponge.digest()
        }

        pub fn new(leaf_hashes: Vec<Fp>) -> Self {
            let leaf_count = leaf_hashes.len();
            let pow2_len = leaf_count.next_power_of_two();
            let tree_depth = pow2_len.trailing_zeros() as usize;
            let internal_node_count = pow2_len - 1; // Internal nodes count

            let mut tree_hashes = vec![Fp::zero(); internal_node_count];

            // Pad leaf hashes to power of 2
            let mut padded_leaves = leaf_hashes.clone();
            padded_leaves.resize(pow2_len, Fp::zero());

            // Compute hashes for internal nodes, bottom-up
            for level in (0..tree_depth).rev() {
                let nodes_at_level = 1 << level;
                let level_start = nodes_at_level - 1;

                for i in 0..nodes_at_level {
                    let left_index = 2 * i;
                    let right_index = left_index + 1;

                    let left_hash = if level == tree_depth - 1 {
                        padded_leaves[left_index]
                    } else {
                        tree_hashes[2 * level_start + left_index + 1]
                    };

                    let right_hash = if level == tree_depth - 1 {
                        padded_leaves[right_index]
                    } else {
                        tree_hashes[2 * level_start + right_index + 1]
                    };

                    tree_hashes[level_start + i] = Self::hash(left_hash, right_hash);
                }
            }

            MerkleTree {
                leaf_hashes,
                tree_hashes,
            }
        }

        /// Returns the root hash.
        pub fn root_hash(&self) -> Fp {
            if self.tree_hashes.is_empty() {
                Fp::zero()
            } else {
                self.tree_hashes[0]
            }
        }

        /// Returns the merkle tree depth
        pub fn depth(&self) -> u32 {
            let leaf_count = self.leaf_hashes.len();
            let pow2_len = leaf_count.next_power_of_two();
            pow2_len.trailing_zeros()
        }

        /// Returns the Merkle path for a given leaf index.
        pub fn merkle_path(&self, leaf_index: usize) -> Vec<(Fp, bool)> {
            let leaf_count = self.leaf_hashes.len();
            let pow2_len = leaf_count.next_power_of_two();
            let tree_depth = pow2_len.trailing_zeros() as usize;

            let mut path = Vec::new();
            let mut current_index = leaf_index;

            for level in (0..tree_depth).rev() {
                let is_left = current_index % 2 != 0;
                let sibling_index = if is_left {
                    current_index - 1
                } else {
                    current_index + 1
                };

                let sibling_hash = if level == tree_depth - 1 {
                    // Sibling at leaf level
                    if sibling_index < self.leaf_hashes.len() {
                        self.leaf_hashes[sibling_index]
                    } else {
                        Fp::zero()
                    }
                } else {
                    // Internal node
                    let level_start = (1 << (level + 1)) - 1;
                    self.tree_hashes[level_start + sibling_index]
                };

                path.push((sibling_hash, is_left));

                // Move up the tree
                current_index /= 2;
            }

            path
        }

        /// Computes the merkle root from a leaf hash and a merkle path.
        pub fn compute_merkle_root(leaf: Fp, path: &[(Fp, bool)]) -> Fp {
            let mut computed = leaf;
            for (sibling, is_left) in path.iter() {
                if *is_left {
                    computed = Self::hash(*sibling, computed);
                } else {
                    computed = Self::hash(computed, *sibling);
                }
            }
            computed
        }

        /// Verifies a leaf hash against a root hash using a Merkle path.
        pub fn verify_merkle_path(leaf: Fp, path: &[(Fp, bool)], root: Fp) -> bool {
            Self::compute_merkle_root(leaf, path) == root
        }

        /// Update a leaf hash and recompute the tree up to the root.
        pub fn update_leaf_and_recompute(&mut self, leaf_index: usize, new_leaf_hash: Fp) {
            self.leaf_hashes[leaf_index] = new_leaf_hash;

            let leaf_count = self.leaf_hashes.len();
            let pow2_len = leaf_count.next_power_of_two();
            let tree_depth = pow2_len.trailing_zeros() as usize;

            let mut current_index = leaf_index;

            for level in (0..tree_depth).rev() {
                let left_index = (current_index / 2) * 2;
                let right_index = left_index + 1;

                let (left_hash, right_hash) = if level == tree_depth - 1 {
                    let left_hash = self.leaf_hashes[left_index];
                    let right_hash = if right_index < self.leaf_hashes.len() {
                        self.leaf_hashes[right_index]
                    } else {
                        Fp::zero()
                    };
                    (left_hash, right_hash)
                } else {
                    let level_start = (1 << (level + 1)) - 1;
                    (
                        self.tree_hashes[level_start + left_index],
                        self.tree_hashes[level_start + right_index],
                    )
                };

                // Move up the tree
                current_index /= 2;

                let level_start = (1 << level) - 1;

                self.tree_hashes[level_start + current_index] = Self::hash(left_hash, right_hash);
            }
        }
    }
}

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

pub struct CommitmentView {
    pub merkle_tree: merkle_tree::MerkleTree,
    pub affine_committed_chunks: Vec<Vesta>,
}

impl CommitmentView {
    fn hash_vesta(commitment: Vesta) -> Fp {
        let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
        fq_sponge.absorb_g(&[commitment]);
        fq_sponge.digest()
    }

    pub fn new(affine_committed_chunks: Vec<Vesta>) -> Self {
        let merkle_tree = {
            let merkle_tree_leaf_hashes = affine_committed_chunks
                .iter()
                .cloned()
                .map(Self::hash_vesta)
                .collect();
            merkle_tree::MerkleTree::new(merkle_tree_leaf_hashes)
        };

        CommitmentView {
            merkle_tree,
            affine_committed_chunks,
        }
    }

    pub fn update(&mut self, index: usize, new_commitment: Vesta) {
        self.affine_committed_chunks[index as usize] = new_commitment;
        let new_hash = Self::hash_vesta(new_commitment);
        self.merkle_tree.update_leaf_and_recompute(index, new_hash);
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Proof {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub challenge: Fp,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub evaluation_point: Fp,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub randomized_data_commitment: Vesta,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub randomized_data_eval: Fp,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub query_commitment: Vesta,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub query_eval: Fp,
    pub opening_proof: OpeningProof<Vesta>,
}

pub fn fast_verify(context: &VerifyContext, proof: &Proof) -> bool {
    let VerifyContext { srs, group_map } = context;
    let Proof {
        challenge: _,
        evaluation_point,
        randomized_data_commitment,
        randomized_data_eval,
        query_commitment,
        query_eval,
        opening_proof,
    } = proof;
    let rng = &mut rand::rngs::OsRng;
    let mut opening_proof_sponge =
        DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
    opening_proof_sponge.absorb_fr(&[*randomized_data_eval]);
    opening_proof_sponge.absorb_fr(&[*query_eval]);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![*evaluation_point],
            polyscale: Fp::one(),
            evalscale: Fp::one(),
            evaluations: vec![Evaluation {
                commitment: PolyComm {
                    chunks: vec![*randomized_data_commitment],
                },
                evaluations: vec![vec![*randomized_data_eval]],
            },Evaluation {
                commitment: PolyComm {
                    chunks: vec![*query_commitment],
                },
                evaluations: vec![vec![*query_eval]],
            }
            ],
            opening: opening_proof,
            combined_inner_product: *randomized_data_eval,
        }],
        rng,
    )
}

pub fn verify(context: &VerifyContext, commitments: &[Vesta], proof: &Proof) -> bool {
    let Proof {
        challenge,
        evaluation_point: _,
        randomized_data_commitment,
        randomized_data_eval: _,
        query_commitment: _,
        query_eval: _,
        opening_proof: _,
    } = proof;

    let powers = commitments
        .iter()
        .scan(Fp::one(), |acc, _| {
            let res = *acc;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    let randomized_data_commitment_expected =
        ProjectiveVesta::msm_bigint(commitments, powers.as_slice()).into_affine();

    *randomized_data_commitment == randomized_data_commitment_expected
        && fast_verify(context, proof)
}

pub struct ProverInputs<'a> {
    pub data: &'a mut [Fp],
    pub commitment_view: CommitmentView,
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
        let commitment_view = CommitmentView::new(affine_committed_chunks);

        ProverInputs {
            commitment_view,
            data,
        }
    }
}

fn prove(context: &VerifyContext, inputs: &ProverInputs) -> Proof {
    let VerifyContext { srs, group_map } = context;
    let rng = &mut rand::rngs::OsRng;
    let ProverInputs {
        commitment_view:
            CommitmentView {
                merkle_tree,
                affine_committed_chunks,
            },
        data,
    } = inputs;

    let mut blinder_sum = Fp::zero();

    let challenge = merkle_tree.root_hash();

    let powers = affine_committed_chunks
        .iter()
        .scan(Fp::one(), |acc, _| {
            let res = *acc;
            blinder_sum += res;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    let randomized_data_commitment =
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

    let query_commitment = srs.h;

    let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );
    fq_sponge.absorb_g(&[randomized_data_commitment]);
    fq_sponge.absorb_g(&[query_commitment]);
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

    let query_poly = ark_poly::univariate::DensePolynomial::zero();

    let query_eval = Fp::zero();

    opening_proof_sponge.absorb_fr(&[randomized_data_eval]);
    opening_proof_sponge.absorb_fr(&[query_eval]);

    let opening_proof = srs.open(
        &group_map,
        &[(
            DensePolynomialOrEvaluations::<_, Radix2EvaluationDomain<_>>::DensePolynomial(
                &randomized_data_poly,
            ),
            PolyComm {
                chunks: vec![blinder_sum],
            },
        ),(
            DensePolynomialOrEvaluations::<_, Radix2EvaluationDomain<_>>::DensePolynomial(
                &query_poly,
            ),
            PolyComm {
                chunks: vec![Fp::one()],
            },
        )
        ],
        &[evaluation_point],
        Fp::one(), // TODO
        Fp::one(), // Single evaluation point, so we don't care
        opening_proof_sponge.clone(),
        rng,
    );

    Proof {
        challenge,
        evaluation_point,
        randomized_data_commitment,
        randomized_data_eval,
        query_commitment,
        query_eval,
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

    use super::{merkle_tree::MerkleTree, CommitmentView, Proof, VerifyContext};
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use mina_curves::pasta::{Fp, Vesta};
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
            #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
            merkle_path: Vec<Fp>,
            // FIXME: This is necessary because serde_as doesn't like the tuple inside the vec
            merkle_directions: Vec<bool>,
        },
        Failure {
            region: u64,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            query_commitment: Vesta,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            precondition_commitment: Vesta,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            data_commitment: Vesta,
            #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
            merkle_path: Vec<Fp>,
            // FIXME: This is necessary because serde_as doesn't like the tuple inside the vec
            merkle_directions: Vec<bool>,
        },
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub enum Message {
        StringMessage(String),
        VerifyProof(Proof),
        ReadIntent(ReadIntent),
        ReadResponse(ReadResponse),
        WriteIntent(WriteIntent),
        WriteResult(WriteResult),
        StorageInitialized {
            size: u64,
            #[serde_as(as = "o1_utils::serialization::SerdeAs")]
            merkle_root: Fp,
        },
    }

    pub fn main(arg: cli::Args) -> ExitCode {
        println!("I'm a network!");

        let cli::Args { address } = arg;

        let verify_context = VerifyContext::new();

        println!("Set up verify context");

        let mut state_replicator_root_hash = Fp::zero();
        let mut state_replicator_commitments = vec![];

        let listener = TcpListener::bind(address).unwrap();
        for stream in listener.incoming() {
            super::rpc_handle(stream.unwrap(), |message| match message {
                Message::StringMessage(i) => println!("stream got data: {}", i),
                Message::VerifyProof(proof) => {
                    println!("Verifying proof");
                    println!("- Fast (non-snark worker) verify");
                    let now = std::time::Instant::now();
                    let valid = super::fast_verify(&verify_context, &proof);
                    let duration = now.elapsed();
                    println!("proof verifies? {}", valid);
                    println!(
                        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                        duration.as_secs(),
                        duration.as_millis(),
                        duration.as_micros(),
                        duration.as_nanos(),
                    );
                    println!("- Slow (snark worker) verify");
                    let now = std::time::Instant::now();
                    let valid =
                        super::verify(&verify_context, &state_replicator_commitments, &proof);
                    let duration = now.elapsed();
                    println!("proof verifies? {}", valid);
                    println!(
                        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
                        duration.as_secs(),
                        duration.as_millis(),
                        duration.as_micros(),
                        duration.as_nanos(),
                    );
                    if !valid {
                        println!("SLASH");
                    }
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
                        "Saw write intent for {region}:\n{:?}\n{:?}\n{:?}",
                        query_commitment, precondition_commitment, data_commitment
                    );
                }
                Message::WriteResult(WriteResult::Success {
                    region,
                    query_commitment,
                    precondition_commitment,
                    data_commitment,
                    old_data_commitment,
                    merkle_path,
                    merkle_directions,
                }) => {
                    let merkle_path: Vec<_> = merkle_path
                        .into_iter()
                        .zip(merkle_directions.into_iter())
                        .collect();
                    let leaf_hash =
                        CommitmentView::hash_vesta(state_replicator_commitments[region as usize]);
                    let is_valid = MerkleTree::verify_merkle_path(
                        leaf_hash,
                        &merkle_path,
                        state_replicator_root_hash,
                    );
                    println!(
                        "Saw write response for {region}:\n{:?}\n{:?}\n{:?}\n{:?}",
                        query_commitment,
                        precondition_commitment,
                        data_commitment,
                        old_data_commitment,
                    );
                    if is_valid {
                        let new_commitment = (state_replicator_commitments[region as usize]
                            + data_commitment
                            - old_data_commitment)
                            .into_affine();
                        state_replicator_commitments[region as usize] = new_commitment;
                        let new_leaf_hash = CommitmentView::hash_vesta(new_commitment);
                        state_replicator_root_hash =
                            MerkleTree::compute_merkle_root(new_leaf_hash, &merkle_path);
                        println!("New root hash:\n{state_replicator_root_hash}");
                    } else {
                        println!("SLASH");
                    }
                }
                Message::WriteResult(WriteResult::Failure {
                    region,
                    query_commitment,
                    precondition_commitment,
                    data_commitment,
                    merkle_path,
                    merkle_directions,
                }) => {
                    println!(
                        "Saw write failure for {region}:\n{:?}\n{:?}\n{:?}",
                        query_commitment, precondition_commitment, data_commitment,
                    );
                    let merkle_path: Vec<_> = merkle_path
                        .into_iter()
                        .zip(merkle_directions.into_iter())
                        .collect();
                    let leaf_hash =
                        CommitmentView::hash_vesta(state_replicator_commitments[region as usize]);
                    let is_valid = MerkleTree::verify_merkle_path(
                        leaf_hash,
                        &merkle_path,
                        state_replicator_root_hash,
                    );
                    if !is_valid {
                        println!("SLASH");
                    }
                }
                Message::StorageInitialized { size, merkle_root } => {
                    let predicted_state_replicator_commitments =
                        vec![verify_context.srs.h; size as usize];
                    // TODO: This can be *way* faster, but this is easy.
                    let expected_merkle_root = {
                        let merkle_tree_leaf_hashes = predicted_state_replicator_commitments
                            .iter()
                            .cloned()
                            .map(CommitmentView::hash_vesta)
                            .collect();
                        MerkleTree::new(merkle_tree_leaf_hashes).root_hash()
                    };
                    let is_valid = expected_merkle_root == merkle_root;
                    println!(
                        "Saw new memory region of size {size}. Merkle root is valid? {is_valid} Root:\n{merkle_root}"
                    );
                    if is_valid {
                        state_replicator_commitments = predicted_state_replicator_commitments;
                        state_replicator_root_hash = merkle_root;
                    } else {
                        println!("SLASH");
                    }
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
    use ark_ff::Zero;
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
            None => DataSource::Data(vec![Fp::zero(); 1 << 20]),
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

        super::rpc_unit(
            network_address.clone(),
            network::Message::StorageInitialized {
                size: prover_inputs.commitment_view.merkle_tree.leaf_hashes.len() as u64,
                merkle_root: prover_inputs.commitment_view.merkle_tree.root_hash(),
            },
        );

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
                        if addresses.len() != values.len() {
                            super::stream_write(stream, Err::<ReadResponse, ()>(()));
                            continue;
                        }
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
                        let merkle_path = prover_inputs
                            .commitment_view
                            .merkle_tree
                            .merkle_path(region as usize);
                        let (merkle_path, merkle_directions): (Vec<_>, Vec<_>) =
                            merkle_path.into_iter().unzip();
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
                                    merkle_path,
                                    merkle_directions,
                                }),
                            );
                            continue;
                        }
                        for (idx, value) in addresses.iter().zip(values.iter()) {
                            prover_inputs.data[SRS_SIZE * region as usize + *idx as usize] = *value;
                        }
                        prover_inputs.commitment_view.update(
                            region as usize,
                            (prover_inputs.commitment_view.affine_committed_chunks
                                [region as usize]
                                + data_commitment
                                - old_data_commitment)
                                .into(),
                        );
                        respond(Ok(WriteResponse::Success));
                        super::rpc_unit(
                            network_address.clone(),
                            network::Message::WriteResult(network::WriteResult::Success {
                                region,
                                query_commitment,
                                precondition_commitment,
                                data_commitment,
                                old_data_commitment,
                                merkle_path,
                                merkle_directions,
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
    pub struct WriteQuery {
        pub region: u64,
        pub addresses: Vec<u64>,
        #[serde_as(as = "Option<Vec<o1_utils::serialization::SerdeAs>>")]
        pub precondition: Option<Vec<Fp>>,
        #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
        pub values: Vec<Fp>,
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
        Write(WriteQuery),
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
                Message::Write(WriteQuery {
                    region,
                    addresses,
                    precondition,
                    values,
                }) => {
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
                    let precondition_commitment = if let Some(precondition) = precondition {
                        Some(
                            {
                                ProjectiveVesta::msm(
                                    address_basis.as_slice(),
                                    precondition.as_slice(),
                                )
                                .unwrap()
                                    + srs.h
                            }
                            .into_affine(),
                        )
                    } else {
                        None
                    };
                    let data_commitment = {
                        ProjectiveVesta::msm(address_basis.as_slice(), values.as_slice()).unwrap()
                            + srs.h
                    }
                    .into_affine();
                    super::rpc_unit(
                        network_address.clone(),
                        network::Message::WriteIntent(network::WriteIntent {
                            region,
                            query_commitment,
                            precondition_commitment,
                            data_commitment,
                        }),
                    );
                    if let Ok(state_provider::WriteResponse::Success) =
                        super::rpc::<_, _, Result<state_provider::WriteResponse, ()>>(
                            state_provider_address.clone(),
                            state_provider::Message::Write(state_provider::WriteQuery {
                                region,
                                addresses,
                                query_commitment,
                                precondition_commitment,
                                data_commitment,
                                values,
                            }),
                        )
                    {
                        super::stream_write(stream, true);
                    } else {
                        super::stream_write(stream, false);
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
            #[command(name = "write")]
            Write(Args),
            #[command(name = "quit")]
            Quit(Args),
        }
    }

    use super::client::{Message as ClientMessage, ReadQuery, ReadResponse, WriteQuery};
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
            cli::Command::Write(args) => {
                let cli::Args { client_address } = args;
                let query = {
                    let reader = serde_json::de::IoRead::new(std::io::stdin());
                    let mut deserializer = serde_json::Deserializer::new(reader);
                    WriteQuery::deserialize(&mut deserializer).unwrap()
                };
                let response: bool = super::rpc(client_address, ClientMessage::Write(query));
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
