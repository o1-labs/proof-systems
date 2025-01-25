use crate::blob::FieldBlob;
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, Radix2EvaluationDomain as D};
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{absorb_commitment, BatchEvaluationProof, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::rngs::OsRng;

//TODO: Where does the challenge come in? Shoud we force different commitments for each time we challenge,
// or only different evaluation points?
pub fn storage_proof<G: KimchiCurve, EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
    srs: &SRS<G>,
    group_map: &G::Map,
    blob: FieldBlob<G>,
    rng: &mut OsRng,
) -> (G::ScalarField, OpeningProof<G>)
where
    G::BaseField: PrimeField,
{
    let alpha = {
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        for commitment in &blob.commitments {
            absorb_commitment(&mut sponge, commitment)
        }
        sponge.challenge()
    };
    let p = {
        let init = (DensePolynomial::zero(), G::ScalarField::one());
        blob.data
            .into_iter()
            .fold(init, |(acc_poly, curr_power), curr_poly| {
                (acc_poly + curr_poly.scale(curr_power), curr_power * alpha)
            })
            .0
    };
    let commitment = srs.commit_non_hiding(&p, 1);
    let (evaluation_point, evaluation) = {
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        sponge.absorb_g(&commitment.chunks);
        let evaluation_point = sponge.challenge();
        (evaluation_point, p.evaluate(&evaluation_point))
    };
    let mut opening_proof_sponge = EFqSponge::new(G::other_curve_sponge_params());
    opening_proof_sponge.absorb_fr(&[evaluation]);

    let proof = srs.open(
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
            G::ScalarField::one(), // Single polynomial, so we don't care
            opening_proof_sponge.clone(),
            rng,
        );
    (evaluation, proof)
}

pub fn verify<G: KimchiCurve, EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
    srs: &SRS<G>,
    group_map: &G::Map,
    commitment: PolyComm<G>,
    evaluation: G::ScalarField,
    opening_proof: &OpeningProof<G>,
    rng: &mut OsRng,
) -> bool
where
    G::BaseField: PrimeField,
{
    let evaluation_point = {
        let mut sponge = EFqSponge::new(G::other_curve_sponge_params());
        sponge.absorb_g(&commitment.chunks);
        sponge.challenge()
    };

    let mut opening_proof_sponge = EFqSponge::new(G::other_curve_sponge_params());
    opening_proof_sponge.absorb_fr(&[evaluation]);

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: opening_proof_sponge.clone(),
            evaluation_points: vec![evaluation_point],
            polyscale: G::ScalarField::one(),
            evalscale: G::ScalarField::one(),
            evaluations: vec![Evaluation {
                commitment,
                evaluations: vec![vec![evaluation]],
            }],
            opening: opening_proof,
            combined_inner_product: evaluation,
        }],
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::{commit_to_field_elems, fold_commitments},
        utils::encode_for_domain,
    };
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use kimchi::groupmap::GroupMap;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use o1_utils::FieldHelpers;
    use once_cell::sync::Lazy;
    use poly_commitment::{commitment::CommitmentCurve, ipa::SRS};
    use proptest::prelude::*;

    const SRS_SIZE: usize = 1 << 16;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| SRS::create(SRS_SIZE));

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
        Lazy::new(|| Radix2EvaluationDomain::new(SRS_SIZE).unwrap());

    static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
        Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

    proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]
    #[test]
        fn test_prove_verify(xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size())
        )
          { let elems = encode_for_domain(&*DOMAIN, &xs);
            let user_commitments = commit_to_field_elems(&*SRS, *DOMAIN, elems);
            let blob = FieldBlob::<Vesta>::encode(&*SRS, *DOMAIN, &xs);
            let mut rng = OsRng;
            let (evaluation, proof) =
                storage_proof::<
                Vesta,
                DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, &*GROUP_MAP, blob, &mut rng);
            let user_commitment = {
                let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
                    mina_poseidon::pasta::fq_kimchi::static_params(),
                );
                fold_commitments(&mut fq_sponge, &user_commitments)
            };
            let res = verify::<
              Vesta,
              DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>>(&*SRS, &*GROUP_MAP, user_commitment, evaluation, &proof, &mut rng);
            prop_assert!(res);
        }
    }
}
