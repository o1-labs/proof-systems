use crate::{blob::FieldBlob, Curve, CurveFqSponge, ScalarField, SRS_SIZE};
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, Radix2EvaluationDomain as D};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm,
};
use rand::rngs::OsRng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::instrument;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageProof {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub evaluation: ScalarField,
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
    let final_chunk = (blob.data.len() / SRS_SIZE) - 1;
    let randomized_data = {
        let mut initial: Vec<ScalarField> = blob.data
            [final_chunk * SRS_SIZE..(final_chunk + 1) * SRS_SIZE]
            .iter()
            .cloned()
            .collect();

        // @volhovm TODO: I don't understand why we only collect data
        // from the final chunk?
        (0..final_chunk).into_iter().rev().for_each(|chunk_ix| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= challenge;
                *acc += blob.data[chunk_ix * SRS_SIZE + idx];
            });
        });
        initial
    };

    let p = {
        let init = (DensePolynomial::zero(), ScalarField::one());
        blob.data
            .into_iter()
            .fold(init, |(acc_poly, curr_power), curr_poly| {
                (
                    acc_poly + curr_poly * curr_power,
                    curr_power * blob.commitments.alpha,
                )
            })
            .0
    };
    let evaluation = p.evaluate(&evaluation_point);
    let opening_proof_sponge = {
        let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
        // TODO: check and see if we need to also absorb the absorb the poly cm
        // see https://github.com/o1-labs/proof-systems/blob/feature/test-data-storage-commitments/data-storage/src/main.rs#L265-L269
        sponge.absorb_fr(&[evaluation]);
        sponge
    };
    let opening_proof =
        srs.open(
            group_map,
            &[
                (
                    DensePolynomialOrEvaluations::<
                        <Curve as AffineRepr>::ScalarField,
                        D<ScalarField>,
                    >::DensePolynomial(&p),
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
        evaluation,
        opening_proof,
    }
}

#[instrument(skip_all, level = "debug")]
pub fn verify_fast(
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    commitment: PolyComm<Curve>,
    evaluation_point: ScalarField,
    proof: &StorageProof,
    rng: &mut OsRng,
) -> bool {
    let mut opening_proof_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    opening_proof_sponge.absorb_fr(&[proof.evaluation]);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![evaluation_point],
            polyscale: ScalarField::one(),
            evalscale: ScalarField::one(),
            evaluations: vec![Evaluation {
                commitment,
                evaluations: vec![vec![proof.evaluation]],
            }],
            opening: &proof.opening_proof,
            combined_inner_product: proof.evaluation,
        }],
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::commit_to_field_elems,
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
        let blob = FieldBlob::<Vesta>::from_bytes::<_, VestaFqSponge>(&*SRS, *DOMAIN, &data);
        let evaluation_point = Fp::rand(&mut rng);
        let proof = prove::<
            Vesta, VestaFqSponge

        >(&*SRS, &*GROUP_MAP, blob, evaluation_point, &mut rng);
        let res = verify_fast::<Vesta, VestaFqSponge>(
            &*SRS,
            &*GROUP_MAP,
            commitment.folded,
            evaluation_point,
            &proof,
            &mut rng,
        );
        prop_assert!(res);
      }
    }
}
