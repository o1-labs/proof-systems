use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC, sponge::DefaultFqSponge, FqSponge as _,
};
use o1_utils::{
    serialization::test_generic_serialization_regression_serde, ExtendedDensePolynomial as _,
};
use poly_commitment::{
    commitment::{
        combined_inner_product, BatchEvaluationProof, BlindedCommitment, CommitmentCurve,
        Evaluation, PolyComm,
    },
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    SRS as _,
};
use rand::{CryptoRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

// Note: Because the current API uses large tuples of types, I re-create types
// in this test to facilitate aggregated proofs and batch verification of proofs.
// TODO: improve the polynomial commitment API

/// A commitment
pub struct Commitment {
    /// the commitment itself, potentially in chunks
    chunked_commitment: PolyComm<Vesta>,
}

/// An evaluated commitment (given a number of evaluation points)
pub struct EvaluatedCommitment {
    /// the commitment
    commit: Commitment,
    /// the chunked evaluations given in the same order as the evaluation points
    chunked_evals: Vec<ChunkedCommitmentEvaluation>,
}

/// A polynomial commitment evaluated at a point. Since a commitment can be
/// chunked, the evaluations can also be chunked.
pub type ChunkedCommitmentEvaluation = Vec<Fp>;

mod prover {
    use super::*;

    /// This struct represents a commitment with associated secret information
    pub struct CommitmentAndSecrets {
        /// the commitment evaluated at some points
        pub eval_commit: EvaluatedCommitment,
        /// the polynomial
        pub poly: DensePolynomial<Fp>,
        /// the blinding part
        pub chunked_blinding: PolyComm<Fp>,
    }
}

/// This struct represents an aggregated evaluation proof for a number of
/// polynomial commitments, as well as a number of evaluation points.
pub struct AggregatedEvaluationProof {
    /// a number of evaluation points
    eval_points: Vec<Fp>,
    /// a number of commitments evaluated at these evaluation points
    eval_commitments: Vec<EvaluatedCommitment>,
    /// the random value used to separate polynomials
    polymask: Fp,
    /// the random value used to separate evaluations
    evalmask: Fp,
    /// an Fq-sponge
    fq_sponge: DefaultFqSponge<VestaParameters, SC, 55>,
    /// the actual evaluation proof
    pub proof: OpeningProof<Vesta, 55>,
}

impl AggregatedEvaluationProof {
    /// This function converts an aggregated evaluation proof into something the
    /// verify API understands
    pub fn verify_type(
        &self,
    ) -> BatchEvaluationProof<
        '_,
        Vesta,
        DefaultFqSponge<VestaParameters, SC, 55>,
        OpeningProof<Vesta, 55>,
        55,
    > {
        let mut coms = vec![];
        for eval_com in &self.eval_commitments {
            assert_eq!(self.eval_points.len(), eval_com.chunked_evals.len());
            coms.push(Evaluation {
                commitment: eval_com.commit.chunked_commitment.clone(),
                evaluations: eval_com.chunked_evals.clone(),
            });
        }

        let combined_inner_product = {
            let es: Vec<_> = coms
                .iter()
                .map(|Evaluation { evaluations, .. }| evaluations.clone())
                .collect();
            combined_inner_product(&self.polymask, &self.evalmask, &es)
        };

        BatchEvaluationProof {
            sponge: self.fq_sponge.clone(),
            evaluation_points: self.eval_points.clone(),
            polyscale: self.polymask,
            evalscale: self.evalmask,
            evaluations: coms,
            opening: &self.proof,
            combined_inner_product,
        }
    }
}

pub fn generate_random_opening_proof<RNG: Rng + CryptoRng>(
    mut rng: &mut RNG,
    group_map: &<Vesta as CommitmentCurve>::Map,
    srs: &SRS<Vesta>,
) -> (Vec<AggregatedEvaluationProof>, Duration, Duration) {
    let num_chunks = 1;

    let fq_sponge = DefaultFqSponge::<VestaParameters, SC, 55>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );

    let mut time_commit = Duration::new(0, 0);
    let mut time_open = Duration::new(0, 0);

    // create 7 distinct "aggregated evaluation proofs"
    let mut proofs = vec![];
    for _ in 0..7 {
        // generate 7 random evaluation points
        let eval_points: Vec<Fp> = (0..7).map(|_| Fp::rand(&mut rng)).collect();

        // create 11 polynomials of random degree (of at most 500)
        // and commit to them
        let mut commitments = vec![];
        for _ in 0..11 {
            let len: usize = rng.gen();
            let len = len % 500;
            // TODO @volhovm maybe remove the second case.
            // every other polynomial is upperbounded
            let poly = if len == 0 {
                DensePolynomial::<Fp>::zero()
            } else {
                DensePolynomial::<Fp>::rand(len, &mut rng)
            };

            // create commitments for each polynomial, and evaluate each
            // polynomial at the 7 random points
            let timer = Instant::now();
            let BlindedCommitment {
                commitment: chunked_commitment,
                blinders: chunked_blinding,
            } = srs.commit(&poly, num_chunks, &mut rng);
            time_commit += timer.elapsed();

            let mut chunked_evals = vec![];
            for point in eval_points.clone() {
                let n = poly.len();
                let num_chunks = if n == 0 {
                    1
                } else {
                    n / srs.g.len() + if n % srs.g.len() == 0 { 0 } else { 1 }
                };
                chunked_evals.push(
                    poly.to_chunked_polynomial(num_chunks, srs.g.len())
                        .evaluate_chunks(point),
                );
            }

            let commit = Commitment { chunked_commitment };

            let eval_commit = EvaluatedCommitment {
                commit,
                chunked_evals,
            };

            commitments.push(prover::CommitmentAndSecrets {
                eval_commit,
                poly,
                chunked_blinding,
            });
        }

        // create aggregated evaluation proof
        let mut polynomials: Vec<(
            DensePolynomialOrEvaluations<Fp, Radix2EvaluationDomain<Fp>>,
            PolyComm<_>,
        )> = vec![];
        for c in &commitments {
            polynomials.push((
                DensePolynomialOrEvaluations::DensePolynomial(&c.poly),
                c.chunked_blinding.clone(),
            ));
        }

        let polymask = Fp::rand(&mut rng);
        let evalmask = Fp::rand(&mut rng);

        let timer = Instant::now();
        let proof = srs.open::<DefaultFqSponge<VestaParameters, SC, 55>, _, _, 55>(
            group_map,
            &polynomials,
            &eval_points.clone(),
            polymask,
            evalmask,
            fq_sponge.clone(),
            &mut rng,
        );
        time_open += timer.elapsed();

        // prepare for batch verification
        let eval_commitments = commitments.into_iter().map(|c| c.eval_commit).collect();
        proofs.push(AggregatedEvaluationProof {
            eval_points,
            eval_commitments,
            polymask,
            evalmask,
            fq_sponge: fq_sponge.clone(),
            proof,
        });
    }

    (proofs, time_commit, time_open)
}

fn test_randomised<RNG: Rng + CryptoRng>(mut rng: &mut RNG) {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    // create an SRS optimized for polynomials of degree 2^7 - 1
    let srs = SRS::<Vesta>::create(1 << 7);

    // TODO: move to bench

    let (proofs, time_commit, time_open) =
        generate_random_opening_proof(&mut rng, &group_map, &srs);

    println!("total commitment time: {:?}", time_commit);
    println!("total evaluation proof creation time: {:?}", time_open);

    let timer = Instant::now();

    // batch verify all the proofs
    let mut batch: Vec<_> = proofs.iter().map(|p| p.verify_type()).collect();
    let result = srs
        .verify::<DefaultFqSponge<VestaParameters, SC, { mina_poseidon::pasta::ROUNDS }>, _, { mina_poseidon::pasta::ROUNDS }>(
            &group_map, &mut batch, &mut rng,
        );
    assert!(result);

    // TODO: move to bench
    println!("batch verification time: {:?}", timer.elapsed());
}

#[test]
/// Tests polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // setup
    let mut rng = o1_utils::tests::make_test_rng(None);
    test_randomised(&mut rng)
}

#[test]
/// Deterministic tests of polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit_deterministic()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // Seed deliberately chosen to exercise zero commitments
    let seed = [
        17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let mut rng = <rand_chacha::ChaCha20Rng as SeedableRng>::from_seed(seed);
    test_randomised(&mut rng)
}

#[test]
pub fn ser_regression_canonical_srs() {
    use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
    use poly_commitment::ipa::SRS;

    let rng = &mut o1_utils::tests::make_test_rng(Some([0u8; 32]));

    let td1 = Fp::rand(rng);
    let data_expected = unsafe { SRS::<Vesta>::create_trusted_setup(td1, 1 << 3) };
    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let buf_expected: Vec<u8> = vec![
        146, 152, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 33, 2, 208, 196, 173, 72, 216, 133, 169, 56, 56, 33, 35,
        130, 78, 164, 182, 235, 78, 233, 153, 95, 96, 113, 78, 110, 205, 98, 59, 183, 156, 34, 26,
        128, 196, 33, 6, 150, 178, 230, 252, 128, 97, 30, 248, 199, 147, 159, 227, 118, 248, 138,
        60, 143, 178, 158, 37, 232, 110, 15, 134, 143, 127, 109, 206, 204, 155, 27, 128, 196, 33,
        64, 90, 121, 139, 173, 254, 255, 108, 129, 22, 165, 14, 110, 147, 48, 189, 183, 210, 237,
        108, 189, 170, 107, 238, 149, 155, 227, 211, 89, 63, 121, 46, 0, 196, 33, 90, 220, 159,
        218, 37, 222, 219, 32, 63, 233, 183, 226, 174, 205, 38, 189, 143, 33, 160, 169, 226, 235,
        216, 43, 17, 29, 215, 31, 150, 233, 163, 36, 0, 196, 33, 98, 225, 126, 245, 162, 255, 249,
        60, 120, 105, 186, 96, 169, 208, 83, 62, 19, 64, 187, 79, 11, 120, 130, 242, 249, 79, 249,
        99, 210, 225, 25, 36, 0, 196, 33, 49, 147, 222, 224, 242, 240, 198, 119, 133, 90, 152, 19,
        122, 52, 255, 181, 14, 55, 81, 250, 47, 167, 47, 195, 36, 7, 187, 103, 225, 0, 169, 26, 0,
        196, 33, 160, 235, 225, 204, 186, 77, 26, 177, 237, 210, 27, 246, 174, 136, 126, 204, 93,
        48, 11, 220, 178, 86, 174, 156, 6, 6, 86, 90, 105, 215, 117, 16, 128, 196, 33, 1, 34, 38,
        38, 91, 206, 178, 229, 168, 199, 139, 226, 117, 121, 162, 156, 54, 54, 120, 117, 99, 242,
        180, 170, 153, 201, 1, 99, 56, 96, 32, 9, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    test_generic_serialization_regression_serde(data_expected, buf_expected);

    let td2 = Fq::rand(rng);
    let data_expected = unsafe { SRS::<Pallas>::create_trusted_setup(td2, 1 << 3) };
    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let buf_expected: Vec<u8> = vec![
        146, 152, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 33, 144, 162, 168, 123, 25, 245, 211, 151, 234, 53, 230,
        184, 254, 200, 193, 156, 214, 207, 155, 171, 186, 143, 221, 21, 24, 49, 159, 187, 221, 215,
        92, 61, 0, 196, 33, 172, 18, 76, 72, 86, 115, 105, 59, 32, 148, 37, 128, 195, 62, 60, 165,
        201, 121, 67, 175, 73, 51, 78, 160, 25, 215, 242, 243, 71, 93, 49, 29, 128, 196, 33, 130,
        19, 51, 124, 82, 66, 228, 1, 66, 62, 240, 98, 240, 241, 101, 177, 252, 8, 42, 36, 76, 215,
        244, 24, 170, 221, 102, 204, 51, 183, 231, 52, 128, 196, 33, 121, 187, 189, 65, 178, 95,
        164, 135, 161, 57, 194, 93, 76, 12, 253, 165, 236, 21, 171, 199, 162, 16, 185, 75, 0, 120,
        171, 4, 1, 21, 184, 1, 0, 196, 33, 165, 208, 157, 8, 127, 129, 67, 81, 56, 223, 87, 125,
        139, 239, 36, 18, 139, 239, 53, 114, 116, 81, 1, 174, 76, 50, 97, 213, 108, 193, 107, 46,
        128, 196, 33, 83, 43, 226, 38, 146, 122, 97, 205, 114, 214, 23, 21, 165, 138, 211, 222,
        224, 190, 130, 70, 142, 203, 203, 89, 49, 138, 144, 104, 8, 247, 147, 11, 128, 196, 33, 73,
        128, 98, 223, 249, 164, 221, 198, 148, 190, 44, 37, 20, 106, 24, 112, 49, 72, 64, 157, 99,
        100, 170, 222, 105, 160, 160, 92, 194, 154, 93, 19, 128, 196, 33, 1, 130, 119, 215, 95,
        139, 130, 47, 90, 13, 171, 187, 79, 106, 134, 121, 50, 181, 54, 202, 63, 25, 38, 174, 42,
        5, 210, 172, 157, 149, 27, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    test_generic_serialization_regression_serde(data_expected, buf_expected);
}

#[test]
pub fn ser_regression_canonical_polycomm() {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use mina_curves::pasta::{Fp, Vesta};
    use poly_commitment::{commitment::BlindedCommitment, ipa::SRS};

    let rng = &mut o1_utils::tests::make_test_rng(Some([0u8; 32]));

    let srs = SRS::<Vesta>::create(1 << 7);

    let com_length = 300;
    let num_chunks = 6;

    let poly = DensePolynomial::<Fp>::rand(com_length, rng);

    let BlindedCommitment {
        commitment: chunked_commitment,
        blinders: _blinders,
    } = srs.commit(&poly, num_chunks, rng);

    let data_expected = chunked_commitment;
    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let buf_expected: Vec<u8> = vec![
        145, 150, 196, 33, 36, 158, 70, 161, 147, 233, 138, 19, 54, 52, 87, 58, 158, 154, 255, 197,
        219, 225, 79, 25, 41, 193, 232, 64, 250, 71, 230, 154, 34, 145, 81, 23, 0, 196, 33, 37,
        227, 246, 88, 42, 44, 53, 244, 102, 92, 197, 246, 56, 56, 135, 155, 248, 155, 243, 23, 76,
        44, 94, 125, 60, 209, 195, 190, 73, 158, 97, 42, 128, 196, 33, 101, 254, 242, 100, 238,
        214, 56, 151, 94, 170, 69, 219, 239, 135, 253, 151, 207, 217, 47, 229, 75, 7, 41, 9, 131,
        205, 85, 171, 166, 213, 96, 52, 128, 196, 33, 53, 166, 32, 175, 166, 196, 121, 1, 25, 236,
        34, 226, 31, 145, 70, 96, 89, 179, 65, 35, 253, 161, 10, 211, 170, 116, 247, 40, 225, 104,
        155, 34, 0, 196, 33, 114, 151, 94, 73, 26, 234, 37, 98, 188, 142, 161, 165, 62, 238, 58,
        76, 200, 16, 62, 210, 124, 127, 229, 81, 119, 145, 43, 157, 254, 237, 154, 57, 128, 196,
        33, 212, 213, 38, 1, 17, 84, 147, 102, 31, 103, 242, 177, 110, 64, 239, 33, 211, 216, 40,
        103, 51, 55, 85, 96, 133, 20, 194, 6, 87, 180, 212, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    test_generic_serialization_regression_serde(data_expected, buf_expected);
}

#[test]
pub fn ser_regression_canonical_opening_proof() {
    use groupmap::GroupMap;
    use mina_curves::pasta::Vesta;
    use poly_commitment::ipa::{OpeningProof, SRS};

    let rng = &mut o1_utils::tests::make_test_rng(Some([0u8; 32]));

    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    let srs = SRS::<Vesta>::create(1 << 7);

    let data_expected: OpeningProof<Vesta, 55> =
        generate_random_opening_proof(rng, &group_map, &srs).0[0]
            .proof
            .clone();

    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let buf_expected: Vec<u8> = vec![
        149, 151, 146, 196, 33, 166, 183, 76, 209, 121, 62, 56, 194, 134, 133, 238, 52, 190, 163,
        234, 149, 245, 202, 234, 70, 56, 187, 130, 25, 73, 135, 136, 95, 248, 80, 124, 39, 128,
        196, 33, 78, 148, 92, 114, 104, 136, 170, 61, 102, 158, 80, 42, 184, 109, 110, 33, 228,
        116, 55, 98, 16, 192, 10, 159, 156, 72, 87, 129, 68, 66, 248, 26, 0, 146, 196, 33, 251, 20,
        242, 183, 87, 51, 106, 226, 80, 224, 139, 186, 33, 52, 203, 117, 6, 129, 167, 88, 252, 193,
        163, 38, 21, 37, 63, 254, 106, 136, 63, 21, 0, 196, 33, 4, 215, 169, 8, 207, 56, 209, 41,
        107, 189, 92, 110, 124, 186, 112, 193, 204, 173, 82, 46, 110, 8, 194, 193, 93, 130, 12,
        216, 24, 151, 94, 61, 128, 146, 196, 33, 55, 26, 135, 155, 211, 30, 67, 184, 93, 78, 146,
        166, 31, 11, 120, 93, 17, 24, 164, 39, 177, 98, 25, 156, 33, 5, 179, 64, 237, 69, 199, 11,
        128, 196, 33, 249, 229, 29, 113, 38, 26, 30, 205, 26, 217, 71, 248, 199, 157, 244, 196, 1,
        108, 74, 39, 173, 55, 118, 216, 191, 232, 27, 95, 190, 38, 96, 35, 128, 146, 196, 33, 109,
        160, 19, 169, 187, 111, 247, 152, 101, 20, 161, 251, 150, 61, 204, 78, 118, 171, 81, 1,
        253, 83, 64, 170, 93, 114, 216, 224, 33, 250, 202, 14, 0, 196, 33, 247, 34, 197, 187, 28,
        46, 42, 6, 126, 129, 132, 151, 39, 150, 115, 138, 229, 50, 220, 8, 170, 81, 173, 13, 54,
        57, 90, 169, 201, 212, 128, 50, 128, 146, 196, 33, 73, 206, 252, 115, 3, 45, 100, 75, 98,
        139, 35, 227, 181, 241, 175, 2, 175, 14, 132, 86, 0, 174, 64, 84, 24, 88, 18, 163, 82, 102,
        164, 19, 0, 196, 33, 128, 62, 85, 80, 76, 1, 35, 195, 197, 48, 46, 1, 13, 183, 105, 91,
        243, 109, 124, 68, 41, 21, 42, 228, 124, 28, 193, 188, 85, 6, 180, 24, 128, 146, 196, 33,
        21, 245, 240, 236, 40, 30, 75, 91, 87, 50, 153, 173, 88, 231, 34, 227, 241, 146, 134, 156,
        217, 161, 155, 165, 76, 142, 69, 82, 45, 49, 163, 56, 0, 196, 33, 247, 220, 178, 199, 227,
        182, 213, 3, 75, 71, 188, 175, 31, 189, 247, 209, 217, 210, 21, 56, 246, 86, 89, 71, 165,
        90, 75, 150, 236, 68, 240, 37, 0, 146, 196, 33, 18, 70, 242, 33, 232, 246, 235, 191, 213,
        96, 68, 75, 173, 43, 125, 25, 239, 71, 93, 71, 74, 159, 50, 34, 251, 139, 133, 228, 241,
        49, 166, 36, 0, 196, 33, 28, 99, 102, 90, 22, 105, 167, 195, 200, 126, 132, 202, 178, 50,
        197, 41, 204, 7, 108, 2, 12, 7, 221, 0, 61, 120, 23, 112, 11, 47, 104, 60, 128, 196, 33,
        34, 178, 82, 48, 155, 153, 34, 99, 173, 221, 221, 236, 235, 5, 135, 165, 18, 39, 120, 175,
        253, 216, 48, 255, 8, 67, 160, 96, 72, 49, 99, 21, 0, 196, 32, 148, 153, 156, 103, 116, 92,
        72, 80, 249, 8, 110, 104, 44, 231, 231, 1, 62, 3, 189, 77, 153, 74, 89, 74, 191, 185, 236,
        20, 209, 93, 77, 51, 196, 32, 33, 224, 176, 185, 62, 76, 18, 58, 48, 219, 106, 206, 35,
        153, 234, 54, 21, 29, 87, 57, 147, 84, 219, 194, 208, 170, 158, 105, 241, 63, 76, 44, 196,
        33, 236, 186, 22, 30, 113, 33, 148, 99, 242, 146, 146, 41, 119, 163, 230, 139, 48, 191, 57,
        161, 79, 240, 7, 167, 28, 62, 213, 170, 132, 195, 255, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    test_generic_serialization_regression_serde(data_expected, buf_expected);
}
