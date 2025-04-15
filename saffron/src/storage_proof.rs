//! This module defines the storage proof prover and verifier. Given a
//! set of commitments C_i and a challenge α the storage proof is just
//! an opening to the combined commitment ∑α^i C_i. Given that α is
//! computed by hashing some external challenge secret (e.g. derived
//! from a hash of a block), and from a hash of the commitments
//! itself, this in essense proves knowledge of the opening to all the
//! commitments C_i simultaneously. Given that α is computed by
//! hashing some external challenge secret (e.g. derived from a hash
//! of a block), and from a hash of the commitments itself, this in
//! essense proves knowledge of the opening to all the commitments C_i
//! simultaneously.

use crate::{
    blob::FieldBlob, Curve, CurveFqSponge, CurveFrSponge, ProjectiveCurve, ScalarField, SRS_SIZE,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D, Radix2EvaluationDomain,
};
use kimchi::{curve::KimchiCurve, plonk_sponge::FrSponge};
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageProof {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub combined_data_eval: ScalarField,
    pub opening_proof: OpeningProof<Curve>,
}

#[instrument(skip_all, level = "debug")]
pub fn prove(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    blob: FieldBlob,
    challenge: ScalarField,
    rng: &mut OsRng,
) -> StorageProof {
    // TODO: Cache this somewhere
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();

    let final_chunk = (blob.data.len() / SRS_SIZE) - 1;
    assert!(blob.data.len() % SRS_SIZE == 0);

    // powers of challenge
    let powers: Vec<_> = blob
        .commitments
        .iter()
        .scan(ScalarField::one(), |acc, _| {
            let res = *acc;
            *acc *= challenge;
            Some(res.into_bigint())
        })
        .collect();

    // ∑_{i=1} com_i^{challenge^i}
    let combined_data_commitment =
        ProjectiveCurve::msm_bigint(blob.commitments.as_slice(), powers.as_slice()).into_affine();

    // Computes ∑_j chal^{j} data[j*SRS_SIZE + i]
    // where j ∈ [0..final_chunk], so the power corresponding to
    // the first chunk is 0 (chal^0 = 1).
    let combined_data: Vec<ScalarField> = {
        let mut initial: Vec<ScalarField> =
            blob.data[final_chunk * SRS_SIZE..(final_chunk + 1) * SRS_SIZE].to_vec();

        (0..final_chunk).rev().for_each(|chunk_ix| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= challenge;
                *acc += blob.data[chunk_ix * SRS_SIZE + idx];
            });
        });

        initial
    };

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[combined_data_commitment]);
    let evaluation_point = fq_sponge.squeeze(2);

    let combined_data_poly = Evaluations::from_vec_and_domain(combined_data, domain).interpolate();
    let combined_data_eval = combined_data_poly.evaluate(&evaluation_point);

    // TODO: Do we need to use fr_sponge? Can't we just use fq_sponge for everything?
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    // TODO: check and see if we need to also absorb the absorb the poly cm
    // see https://github.com/o1-labs/proof-systems/blob/feature/test-data-storage-commitments/data-storage/src/main.rs#L265-L269
    fr_sponge.absorb(&combined_data_eval);

    let opening_proof =
        srs.open(
            group_map,
            &[
                (
                    DensePolynomialOrEvaluations::<
                        <Curve as AffineRepr>::ScalarField,
                        D<ScalarField>,
                    >::DensePolynomial(&combined_data_poly),
                    PolyComm {
                        chunks: vec![ScalarField::zero()],
                    },
                ),
            ],
            &[evaluation_point],
            ScalarField::one(), // Single evaluation, so we don't care
            ScalarField::one(), // Single evaluation, so we don't care
            fq_sponge_before_evaluations,
            rng,
        );

    StorageProof {
        combined_data_eval,
        opening_proof,
    }
}

#[instrument(skip_all, level = "debug")]
pub fn verify_wrt_combined_data_commitment(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    combined_data_commitment: Curve,
    proof: &StorageProof,
    rng: &mut OsRng,
) -> bool {
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    let evaluation_point = {
        fq_sponge.absorb_g(&[combined_data_commitment]);
        fq_sponge.squeeze(2)
    };

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    // TODO: check and see if we need to also absorb the absorb the poly cm
    // see https://github.com/o1-labs/proof-systems/blob/feature/test-data-storage-commitments/data-storage/src/main.rs#L265-L269
    fr_sponge.absorb(&proof.combined_data_eval);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: fq_sponge_before_evaluations,
            evaluation_points: vec![evaluation_point],
            polyscale: ScalarField::one(),
            evalscale: ScalarField::one(),
            evaluations: vec![Evaluation {
                commitment: PolyComm {
                    chunks: vec![combined_data_commitment],
                },
                evaluations: vec![vec![proof.combined_data_eval]],
            }],
            opening: &proof.opening_proof,
            combined_inner_product: proof.combined_data_eval,
        }],
        rng,
    )
}

#[instrument(skip_all, level = "debug")]
pub fn verify(
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
    let combined_data_commitment =
        ProjectiveCurve::msm_bigint(commitments, powers.as_slice()).into_affine();

    verify_wrt_combined_data_commitment(srs, group_map, combined_data_commitment, proof, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::{combine_commitments, commit_to_field_elems},
        env,
        utils::{encode_for_domain, test_utils::UserData},
    };

    use ark_ff::UniformRand;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use kimchi::groupmap::GroupMap;
    use mina_curves::pasta::{Fp, Vesta};
    use once_cell::sync::Lazy;
    use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
    use proptest::prelude::*;

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
        let commitments = {
              let field_elems: Vec<_> = encode_for_domain(DOMAIN.size(), &data).into_iter().flatten().collect();
              commit_to_field_elems(&SRS, &field_elems)
        };

        // extra seed
        let challenge_seed: ScalarField = ScalarField::rand(&mut rng);

        let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
        sponge.absorb_fr(&[challenge_seed]);
        let (combined_data_commitment, challenge) =
            combine_commitments(&mut sponge, commitments.as_slice());

        let blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &data);

        let proof = prove(&SRS, &GROUP_MAP, blob, challenge, &mut rng);
        let res = verify_wrt_combined_data_commitment(
            &SRS,
            &GROUP_MAP,
            combined_data_commitment,
            &proof,
            &mut rng,
        );
        prop_assert!(res);
      }
    }

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]
    #[test]
    fn test_storage_soundness(UserData(data) in UserData::arbitrary()) {
        let mut rng = OsRng;
        let commitments = {
              let field_elems: Vec<_> = encode_for_domain(DOMAIN.size(), &data).into_iter().flatten().collect();
              commit_to_field_elems(&SRS, &field_elems)
        };

        // extra seed
        let challenge_seed: ScalarField = ScalarField::rand(&mut rng);

        let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
        sponge.absorb_fr(&[challenge_seed]);
        let (combined_data_commitment, challenge) =
            combine_commitments(&mut sponge, commitments.as_slice());

        let blob = FieldBlob::from_bytes::<_>(&SRS, *DOMAIN, &data);

        let proof = prove(&SRS, &GROUP_MAP, blob, challenge, &mut rng);

        let proof_malformed_1 = {
            StorageProof {
                combined_data_eval: proof.combined_data_eval + ScalarField::one(),
                opening_proof: proof.opening_proof.clone(),
            }
        };

        let res_1 = verify_wrt_combined_data_commitment(
            &SRS,
            &GROUP_MAP,
            combined_data_commitment,
            &proof_malformed_1,
            &mut rng,
        );

        prop_assert!(!res_1);

        let proof_malformed_2 = {
            let mut opening_proof = proof.opening_proof.clone();
            opening_proof.z1 = ScalarField::one();
            StorageProof {
                combined_data_eval: proof.combined_data_eval,
                opening_proof,
            }
        };

        let res_2 = verify_wrt_combined_data_commitment(
            &SRS,
            &GROUP_MAP,
            combined_data_commitment,
            &proof_malformed_2,
            &mut rng,
        );

        prop_assert!(!res_2);
      }
    }
}
