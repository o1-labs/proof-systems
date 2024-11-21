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

pub fn main() -> ExitCode {
    const SRS_SIZE: usize = 1 << 16;

    println!("Generate SRS");
    let now = std::time::Instant::now();
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
    let srs = SRS::<Vesta>::create(SRS_SIZE);
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );
    println!("Generate SRS lagrange basis");

    let basis = srs
        .get_lagrange_basis(domain)
        .iter()
        .map(|x| x.chunks[0])
        .collect::<Vec<_>>();
    let basis = basis.as_slice();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    const DATA_SIZE: usize = 1 << 25;

    println!("Generate some random data of size {}", DATA_SIZE);
    let now = std::time::Instant::now();
    let rng = &mut rand::rngs::OsRng;
    let data = (0..DATA_SIZE)
        .map(|_| <Fp as UniformRand>::rand(rng).into_bigint())
        .collect::<Vec<_>>();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Committing to the data");
    let now = std::time::Instant::now();
    let committed_chunks = (0..data.len() / SRS_SIZE)
        .into_par_iter()
        .map(|idx| ProjectiveVesta::msm_bigint(basis, &data[SRS_SIZE * idx..SRS_SIZE * (idx + 1)]))
        .collect::<Vec<_>>();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Convert to affine coordinates");
    let now = std::time::Instant::now();
    let affine_committed_chunks = ProjectiveVesta::normalize_batch(committed_chunks.as_slice());
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Hashing the commitments");
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
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Computing powers");
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
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Combining the commitments");
    let now = std::time::Instant::now();
    let final_commitment =
        ProjectiveVesta::msm_bigint(affine_committed_chunks.as_slice(), powers.as_slice())
            .into_affine();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Convert data (because we don't have the Montgomery hack yet)");
    let now = std::time::Instant::now();
    let mongomeryized_data = data
        .into_iter()
        .map(|x| Fp::from_bigint(x).unwrap())
        .collect::<Vec<_>>();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Compute combined polynomial");
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
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Evaluation point");
    let now = std::time::Instant::now();
    let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );
    fq_sponge.absorb_g(&[final_commitment]);
    let evaluation_point = fq_sponge.squeeze(2);
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Interpolate polynomial (fixed cost)");
    let now = std::time::Instant::now();
    let randomized_data_poly =
        Evaluations::from_vec_and_domain(randomized_data, domain).interpolate();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Evaluate polynomial and absorb evaluation (fixed cost)");
    let now = std::time::Instant::now();
    let randomized_data_eval = randomized_data_poly.evaluate(&evaluation_point);
    let mut opening_proof_sponge =
        DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
            mina_poseidon::pasta::fq_kimchi::static_params(),
        );
    opening_proof_sponge.absorb_fr(&[randomized_data_eval]);
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Group map (setup");
    let now = std::time::Instant::now();
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let duration = now.elapsed();
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Opening proof (fixed cost regardless of data size)");
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
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    println!("Verify opening proof");
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
    println!("Verifies: {}", opening_proof_verifies);
    println!(
        "Took {:?}s / {:?}ms / {:?}us / {:?}ns",
        duration.as_secs(),
        duration.as_millis(),
        duration.as_micros(),
        duration.as_nanos(),
    );

    ExitCode::SUCCESS
}
