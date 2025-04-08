use ark_ff::{One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use kimchi::groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge as _,
};
use poly_commitment::{
    commitment::{absorb_commitment, BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::SRS,
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use saffron::utils::encode_for_domain;
use std::{fs::File, io::Read, process::ExitCode};

// To run:
// ```
// cargo run --bin saffron-og-flow --release -- <path-to-file>
// ```

pub fn main() -> ExitCode {
    let input_file = std::env::args()
        .nth(1)
        .ok_or("Missing data filepath argument")
        .unwrap();

    println!("Startup time (cacheable, 1-time cost)");

    println!("- Generate SRS");
    let now = std::time::Instant::now();
    let domain = Radix2EvaluationDomain::new(saffron::SRS_SIZE).unwrap();
    let srs = SRS::<Vesta>::create(saffron::SRS_SIZE);
    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );
    println!("- Generate SRS lagrange basis");
    let basis = srs.get_lagrange_basis(domain);
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

    let now = std::time::Instant::now();
    let rng = &mut rand::rngs::OsRng;

    println!("Reading data from {}", input_file);
    let data: Vec<Fp> = {
        let mut file = File::open(input_file).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        encode_for_domain(domain.size(), &buf)
            .into_iter()
            .flatten()
            .collect()
    };

    let duration = now.elapsed();
    println!(
        "  - Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Main protocol");

    println!("- One-time setup for newly-stored data");
    println!("  - Generate cryptographic commitments");
    let now = std::time::Instant::now();
    let committed_chunks = (0..data.len() / saffron::SRS_SIZE)
        .into_par_iter()
        .map(|idx| {
            PolyComm::multi_scalar_mul(
                &basis.iter().collect::<Vec<_>>(),
                &data[saffron::SRS_SIZE * idx..saffron::SRS_SIZE * (idx + 1)],
            )
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

    println!(" - Convert to affine coordinates");
    let now = std::time::Instant::now();
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
    committed_chunks.iter().for_each(|commitment| {
        absorb_commitment(&mut fq_sponge, commitment);
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
        println!("- Storage protocol iteration {i}");
        println!("  - Computing randomizers for data chunks");
        let now = std::time::Instant::now();
        let powers = committed_chunks
            .iter()
            .scan(Fp::one(), |acc, _| {
                let res = *acc;
                *acc *= challenge;
                Some(res)
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
        let final_commitment = PolyComm::multi_scalar_mul(
            &committed_chunks.iter().collect::<Vec<_>>(),
            powers.as_slice(),
        );
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
        let mongomeryized_data = data.iter().map(|x| Fp::from(*x)).collect::<Vec<_>>();
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
        let final_chunk = (mongomeryized_data.len() / saffron::SRS_SIZE) - 1;
        let randomized_data = (0..saffron::SRS_SIZE)
            .into_par_iter()
            .map(|idx| {
                let mut acc = mongomeryized_data[final_chunk * saffron::SRS_SIZE + idx];
                (0..final_chunk).rev().for_each(|chunk| {
                    acc *= challenge;
                    acc += mongomeryized_data[chunk * saffron::SRS_SIZE + idx];
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
        absorb_commitment(&mut fq_sponge, &final_commitment);
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
                    commitment: final_commitment,
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
