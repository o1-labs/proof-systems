use crate::{blob::FieldBlob, Curve, CurveFqSponge, ProjectiveCurve, ScalarField, SRS_SIZE};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D, Radix2EvaluationDomain,
};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm,
};
use rand::rngs::OsRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::instrument;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageProof {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub randomized_data_eval: ScalarField,
    pub opening_proof: OpeningProof<Curve>,
}

#[instrument(skip_all, level = "debug")]
pub fn prove(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    blob: FieldBlob,
    challenge: ScalarField, // this could be merkle tree root
    rng: &mut OsRng,
) -> StorageProof {
    // TODO: Cache this somewhere
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();

    let final_chunk = (blob.data.len() / SRS_SIZE) - 1;
    assert!(blob.data.len() % SRS_SIZE == 0);

    let powers = blob
        .commitments
        .iter()
        .scan(ScalarField::one(), |acc, _| {
            let res = *acc;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    let randomized_data_commitment =
        ProjectiveCurve::msm_bigint(blob.commitments.as_slice(), powers.as_slice()).into_affine();

    // Computes ∑_j chal^{j} data[j*SRS_SIZE + i]
    // where j ∈ [0..final_chunk], so the power corresponding to
    // the first chunk is 0 (chal^0 = 1).
    let randomized_data = {
        let mut initial: Vec<ScalarField> = blob.data
            [final_chunk * SRS_SIZE..(final_chunk + 1) * SRS_SIZE]
            .iter()
            .cloned()
            .collect();

        (0..final_chunk).into_iter().rev().for_each(|chunk_ix| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= challenge;
                *acc += blob.data[chunk_ix * SRS_SIZE + idx];
            });
        });

        initial
    };

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[randomized_data_commitment]);
    let evaluation_point = fq_sponge.squeeze(2);

    let randomized_data_poly =
        Evaluations::from_vec_and_domain(randomized_data, domain).interpolate();
    let randomized_data_eval = randomized_data_poly.evaluate(&evaluation_point);
    let mut opening_proof_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    // TODO: check and see if we need to also absorb the absorb the poly cm
    // see https://github.com/o1-labs/proof-systems/blob/feature/test-data-storage-commitments/data-storage/src/main.rs#L265-L269
    opening_proof_sponge.absorb_fr(&[randomized_data_eval]);

    let opening_proof =
        srs.open(
            group_map,
            &[
                (
                    DensePolynomialOrEvaluations::<
                        <Curve as AffineRepr>::ScalarField,
                        D<ScalarField>,
                    >::DensePolynomial(&randomized_data_poly),
                    PolyComm {
                        chunks: vec![ScalarField::zero()],
                    },
                ),
            ],
            &[evaluation_point],
            ScalarField::one(), // Single evaluation, so we don't care
            ScalarField::one(), // Single evaluation, so we don't care
            opening_proof_sponge,
            rng,
        );

    StorageProof {
        randomized_data_eval,
        opening_proof,
    }
}

#[instrument(skip_all, level = "debug")]
pub fn verify_fast(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    randomized_data_commitment: Curve,
    proof: &StorageProof,
    rng: &mut OsRng,
) -> bool {
    let evaluation_point = {
        let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
        fq_sponge.absorb_g(&[randomized_data_commitment]);
        fq_sponge.squeeze(2)
    };

    let mut opening_proof_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    opening_proof_sponge.absorb_fr(&[proof.randomized_data_eval]);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![evaluation_point],
            polyscale: ScalarField::one(),
            evalscale: ScalarField::one(),
            evaluations: vec![Evaluation {
                commitment: PolyComm {
                    chunks: vec![randomized_data_commitment],
                },
                evaluations: vec![vec![proof.randomized_data_eval]],
            }],
            opening: &proof.opening_proof,
            combined_inner_product: proof.randomized_data_eval,
        }],
        rng,
    )
}

#[instrument(skip_all, level = "debug")]
pub fn verify_full(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    commitments: &[Curve],
    challenge: ScalarField, // this could be merkle tree root
    proof: &StorageProof,
    rng: &mut OsRng,
) -> bool {
    let powers = commitments
        .iter()
        .scan(ScalarField::one(), |acc, _| {
            let res = *acc;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect::<Vec<_>>();

    // randomised data commitment is ∏ C_i^{chal^i} for all chunks
    let randomized_data_commitment =
        ProjectiveCurve::msm_bigint(commitments, powers.as_slice()).into_affine();

    verify_fast(srs, group_map, randomized_data_commitment, proof, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::{commit_to_field_elems, fold_commitments},
        env,
        utils::{encode_for_domain, test_utils::UserData},
    };
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::UniformRand;
    use kimchi::groupmap::GroupMap;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use once_cell::sync::Lazy;
    use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
    use proptest::prelude::*;

    type VestaFqSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(1 << 16)
        }
    });

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS.size()).unwrap());

    static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
        Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]
    #[test]
    fn test_storage_prove_verify(UserData(data) in UserData::arbitrary()) {
        let mut rng = OsRng;
        let commitment = {
            let field_elems = encode_for_domain(&*DOMAIN, &data);
            commit_to_field_elems::<_, VestaFqSponge>(&*SRS, *DOMAIN, field_elems)
        };
        let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
        let (randomized_data_commitment, challenge) =
            fold_commitments(&mut sponge, commitment.chunks.as_slice());

        let blob = FieldBlob::from_bytes::<_>(&*SRS, *DOMAIN, &data);


        let proof = prove(&*SRS, &*GROUP_MAP, blob, challenge, &mut rng);
        let res = verify_fast(
            &*SRS,
            &*GROUP_MAP,
            randomized_data_commitment.chunks[0],
            &proof,
            &mut rng,
        );
        prop_assert!(res);
      }
    }
}
