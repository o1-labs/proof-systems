use crate::{
    blob::FieldBlob,
    commitment::{fold_commitments, Commitment},
};
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
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::instrument;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "G::ScalarField : CanonicalDeserialize + CanonicalSerialize")]
pub struct StorageProof<G: CommitmentCurve> {
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub evaluation: G::ScalarField,
    pub opening_proof: OpeningProof<G>,
}

#[instrument(skip_all, level = "debug")]
pub fn storage_proof<G: KimchiCurve, EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
    srs: &SRS<G>,
    group_map: &G::Map,
    blob: FieldBlob<G>,
    evaluation_point: G::ScalarField,
    rng: &mut OsRng,
    alpha: G::ScalarField,
) -> StorageProof<G>
where
    G::BaseField: PrimeField,
{
    let p = {
        let init = (DensePolynomial::zero(), G::ScalarField::one());
        blob.chunks
            .into_iter()
            .fold(init, |(acc_poly, curr_power), curr_poly| {
                (acc_poly + curr_poly.scale(curr_power), curr_power * alpha)
            })
            .0
    };
    let evaluation = p.evaluate(&evaluation_point);
    let opening_proof_sponge = {
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        // TODO: check and see if we need to also absorb the absorb the poly cm
        // see https://github.com/o1-labs/proof-systems/blob/feature/test-data-storage-commitments/data-storage/src/main.rs#L265-L269
        sponge.absorb_fr(&[evaluation]);
        sponge
    };
    let opening_proof = srs.open(
            group_map,
            &[(
                DensePolynomialOrEvaluations::<<G as AffineRepr>::ScalarField, D<G::ScalarField>> ::DensePolynomial(
                    &p,
                ),
                PolyComm {
                    chunks: vec![G::ScalarField::zero()],
                },
            )],
            &[evaluation_point],
            G::ScalarField::one(), // Single polynomial, so we don't care
            G::ScalarField::one(), // Single evaluation, so we don't care
            opening_proof_sponge,
            rng,
        );
    StorageProof {
        evaluation,
        opening_proof,
    }
}

#[instrument(skip_all, level = "debug")]
pub fn verify_storage_proof<
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
>(
    srs: &SRS<G>,
    group_map: &G::Map,
    commitment: Commitment<G>,
    evaluation_point: G::ScalarField,
    proof: &StorageProof<G>,
    rng: &mut OsRng,
    alpha: G::ScalarField,
) -> bool
where
    G::BaseField: PrimeField,
{
    let mut opening_proof_sponge = EFqSponge::new(G::other_curve_sponge_params());
    opening_proof_sponge.absorb_fr(&[proof.evaluation]);
    let combined_commitment = fold_commitments::<_, EFqSponge>(alpha, &commitment.chunks);
    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![evaluation_point],
            polyscale: G::ScalarField::one(),
            evalscale: G::ScalarField::one(),
            evaluations: vec![Evaluation {
                commitment: combined_commitment,
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
        let blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &data);
        let evaluation_point = Fp::rand(&mut rng);
        let alpha = Fp::rand(&mut rng);
        let proof = storage_proof::<
            Vesta, VestaFqSponge

        >(&*SRS, &*GROUP_MAP, blob, evaluation_point, &mut rng, alpha);
        let res = verify_storage_proof::<Vesta, VestaFqSponge>(
            &*SRS,
            &*GROUP_MAP,
            commitment,
            evaluation_point,
            &proof,
            &mut rng,
            alpha,
        );
        prop_assert!(res);
      }
    }
}
