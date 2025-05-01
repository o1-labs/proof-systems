//! Folding version of the read prover.

use crate::{Curve, CurveFqSponge, CurveFrSponge, ScalarField, SRS_SIZE};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D,
};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{combined_inner_product, BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::{CryptoRng, RngCore};

#[derive(PartialEq, Eq)]
pub struct RelaxedInstance {
    u: ScalarField,
    comm_d: Curve,
    comm_q: Curve,
    comm_a: Curve,
    comm_e: Curve,
}

#[derive(PartialEq, Eq)]
pub struct RelaxedWitness {
    d: Evaluations<ScalarField, R2D<ScalarField>>,
    q: Evaluations<ScalarField, R2D<ScalarField>>,
    a: Evaluations<ScalarField, R2D<ScalarField>>,
    e: Evaluations<ScalarField, R2D<ScalarField>>,
}

impl RelaxedInstance {
    pub fn check_in_language(&self, srs: &SRS<Curve>, wit: &RelaxedWitness) -> bool {
        for i in 0..SRS_SIZE {
            // todo can be parallelized
            if self.u * wit.a[i] - wit.q[i] * wit.d[i] + wit.e[i] != ScalarField::zero() {
                return false;
            }
        }
        if self.comm_a
            != srs
                .commit_non_hiding(&wit.a.clone().interpolate(), 1)
                .chunks[0]
        {
            return false;
        }
        if self.comm_d
            != srs
                .commit_non_hiding(&wit.d.clone().interpolate(), 1)
                .chunks[0]
        {
            return false;
        }
        if self.comm_q
            != srs
                .commit_non_hiding(&wit.q.clone().interpolate(), 1)
                .chunks[0]
        {
            return false;
        }
        if self.comm_e
            != srs
                .commit_non_hiding(&wit.e.clone().interpolate(), 1)
                .chunks[0]
        {
            return false;
        }
        true
    }
}

// the first instance/witness is supposed to be non-relaxed
pub fn folding_prover(
    srs: &SRS<Curve>,
    inst1: &RelaxedInstance,
    inst2: &RelaxedInstance,
    wit1: &RelaxedWitness,
    wit2: &RelaxedWitness,
) -> (RelaxedInstance, RelaxedWitness, Curve) {
    assert!(inst1.u == ScalarField::one());
    assert!(inst1.comm_e == Curve::zero());

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let error_term: Evaluations<ScalarField, R2D<ScalarField>> =
        &(&(&wit2.a + &(&wit1.a * inst2.u)) - &(&wit2.q * &wit1.d)) - &(&wit1.q * &wit2.d);

    let error_comm: Curve = srs
        .commit_non_hiding(&error_term.clone().interpolate(), 1)
        .chunks[0];

    fq_sponge.absorb_g(&[
        inst1.comm_d,
        inst1.comm_q,
        inst1.comm_a,
        inst1.comm_e,
        inst2.comm_d,
        inst2.comm_q,
        inst2.comm_a,
        inst2.comm_e,
        error_comm,
    ]);

    let recombination_chal = fq_sponge.squeeze(2);

    let a3 = &wit1.a + &(&wit2.a * recombination_chal);
    let q3 = &wit1.q + &(&wit2.q * recombination_chal);
    let d3 = &wit1.d + &(&wit2.d * recombination_chal);

    let comm_a3 = inst1.comm_a + inst2.comm_a * recombination_chal;
    let comm_q3 = inst1.comm_q + inst2.comm_q * recombination_chal;
    let comm_d3 = inst1.comm_d + inst2.comm_d * recombination_chal;

    let new_u = ScalarField::one() + recombination_chal * inst2.u;

    let e3 = &(&wit2.e * (recombination_chal * recombination_chal))
        - &(&error_term * recombination_chal);
    let comm_e3 =
        inst2.comm_e * (recombination_chal * recombination_chal) - error_comm * recombination_chal;

    let new_inst = RelaxedInstance {
        u: new_u,
        comm_d: comm_d3.into(),
        comm_q: comm_q3.into(),
        comm_a: comm_a3.into(),
        comm_e: comm_e3.into(),
    };

    let new_wit = RelaxedWitness {
        d: d3,
        q: q3,
        a: a3,
        e: e3,
    };

    (new_inst, new_wit, error_comm)
}

pub fn folding_verifier(
    inst1: &RelaxedInstance,
    inst2: &RelaxedInstance,
    error_comm: Curve,
) -> RelaxedInstance {
    assert!(inst1.u == ScalarField::one());
    assert!(inst1.comm_e == Curve::zero());

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[
        inst1.comm_d,
        inst1.comm_q,
        inst1.comm_a,
        inst1.comm_e,
        inst2.comm_d,
        inst2.comm_q,
        inst2.comm_a,
        inst2.comm_e,
        error_comm,
    ]);

    let recombination_chal = fq_sponge.squeeze(2);

    let comm_a3 = inst1.comm_a + inst2.comm_a * recombination_chal;
    let comm_q3 = inst1.comm_q + inst2.comm_q * recombination_chal;
    let comm_d3 = inst1.comm_d + inst2.comm_d * recombination_chal;

    let new_u = ScalarField::one() + recombination_chal * inst2.u;

    let comm_e3 =
        inst2.comm_e * (recombination_chal * recombination_chal) - error_comm * recombination_chal;

    RelaxedInstance {
        u: new_u,
        comm_d: comm_d3.into(),
        comm_q: comm_q3.into(),
        comm_a: comm_a3.into(),
        comm_e: comm_e3.into(),
    }
}

#[derive(Debug, Clone)]
pub struct ReadProof {
    // Commitment of quotient polynomial T (aka t_comm)
    pub quotient_comm: Curve,

    // Evaluation of data polynomial at the required challenge point
    pub data_eval: ScalarField,
    // Evaluation of query polynomial at the required challenge point
    pub query_eval: ScalarField,
    // Evaluation of answer polynomial at the required challenge point
    pub answer_eval: ScalarField,
    // Evaluation of error polynomial at the required challenge point
    pub error_eval: ScalarField,

    // Polynomial commitment’s proof for the validity of returned evaluations
    pub opening_proof: OpeningProof<Curve>,
}

pub fn prove_relaxed<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    inst: &RelaxedInstance,
    wit: &RelaxedWitness,
) -> ReadProof
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    // TODO we assume that (inst,wit) ∈ L, that is inst.comm_d = Com(wit.d), etc.

    let data_poly: DensePolynomial<ScalarField> = wit.d.interpolate_by_ref();
    let query_poly: DensePolynomial<ScalarField> = wit.q.interpolate_by_ref();
    let answer_poly: DensePolynomial<ScalarField> = wit.a.interpolate_by_ref();
    let error_poly: DensePolynomial<ScalarField> = wit.e.interpolate_by_ref();

    fq_sponge.absorb_g(&[inst.comm_d, inst.comm_q, inst.comm_a, inst.comm_e]);

    // quotient poly is (d * q - a * u + e) / (X^N-1)
    let quotient_poly: DensePolynomial<ScalarField> = {
        let data_d2 = data_poly.evaluate_over_domain_by_ref(domain.d2);
        let query_d2 = query_poly.evaluate_over_domain_by_ref(domain.d2);
        let answer_d2 = answer_poly.evaluate_over_domain_by_ref(domain.d2);
        let error_d2 = error_poly.evaluate_over_domain_by_ref(domain.d2);

        // q×d - a
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
            &(&(&answer_d2 * inst.u) - &(&data_d2 * &query_d2)) + &error_d2;

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let fail_final_q_division = || panic!("Division by vanishing poly must not fail");
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = numerator_eval_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);
        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !res.is_zero() {
            fail_final_q_division();
        }

        quotient
    };

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
    let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1).chunks[0];
    fq_sponge.absorb_g(&[quotient_comm]);

    // aka zeta
    let evaluation_point = fq_sponge.challenge();

    // Fiat Shamir - absorbing evaluations
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let data_eval = data_poly.evaluate(&evaluation_point);
    let query_eval = query_poly.evaluate(&evaluation_point);
    let answer_eval = answer_poly.evaluate(&evaluation_point);
    let error_eval = error_poly.evaluate(&evaluation_point);
    let quotient_eval = quotient_poly.evaluate(&evaluation_point);

    for eval in [
        data_eval,
        query_eval,
        answer_eval,
        error_eval,
        quotient_eval,
    ]
    .into_iter()
    {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);

    // Creating the polynomials for the batch proof
    // Gathering all polynomials to use in the opening proof
    let opening_proof_inputs: Vec<_> = {
        let coefficients_form =
            DensePolynomialOrEvaluations::<_, R2D<ScalarField>>::DensePolynomial;
        let non_hiding = |n_chunks| PolyComm {
            chunks: vec![ScalarField::zero(); n_chunks],
        };

        vec![
            (coefficients_form(&data_poly), non_hiding(1)),
            (coefficients_form(&query_poly), non_hiding(1)),
            (coefficients_form(&answer_poly), non_hiding(1)),
            (coefficients_form(&error_poly), non_hiding(1)),
            (coefficients_form(&quotient_poly), non_hiding(1)),
        ]
    };

    let opening_proof = srs.open(
        group_map,
        opening_proof_inputs.as_slice(),
        &[evaluation_point],
        polyscale,
        evalscale,
        fq_sponge,
        rng,
    );

    ReadProof {
        quotient_comm,
        data_eval,
        query_eval,
        answer_eval,
        error_eval,
        opening_proof,
    }
}

pub fn verify_relaxed<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    inst: &RelaxedInstance,
    proof: &ReadProof,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[inst.comm_d, inst.comm_q, inst.comm_a, inst.comm_e]);
    fq_sponge.absorb_g(&[proof.quotient_comm]);

    let evaluation_point = fq_sponge.challenge();

    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let vanishing_poly_at_zeta = domain.d1.vanishing_polynomial().evaluate(&evaluation_point);
    let quotient_eval = {
        (inst.u * proof.answer_eval - proof.data_eval * proof.query_eval + proof.error_eval)
            * vanishing_poly_at_zeta
                .inverse()
                .unwrap_or_else(|| panic!("Inverse fails only with negligible probability"))
    };

    for eval in [
        proof.data_eval,
        proof.query_eval,
        proof.answer_eval,
        proof.error_eval,
        quotient_eval,
    ]
    .into_iter()
    {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);

    let coms_and_evaluations = vec![
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.comm_d],
            },
            evaluations: vec![vec![proof.data_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.comm_q],
            },
            evaluations: vec![vec![proof.query_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.comm_a],
            },
            evaluations: vec![vec![proof.answer_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.comm_e],
            },
            evaluations: vec![vec![proof.error_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.quotient_comm],
            },
            evaluations: vec![vec![quotient_eval]],
        },
    ];
    let combined_inner_product = {
        let evaluations: Vec<_> = coms_and_evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&polyscale, &evalscale, evaluations.as_slice())
    };

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: fq_sponge,
            evaluation_points: vec![evaluation_point],
            polyscale,
            evalscale,
            evaluations: coms_and_evaluations,
            opening: &proof.opening_proof,
            combined_inner_product,
        }],
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env, Curve, ScalarField, SRS_SIZE};
    use ark_ec::AffineRepr;
    use ark_ff::{One, UniformRand};
    use ark_poly::{univariate::DensePolynomial, Evaluations};
    use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
    use mina_curves::pasta::{Fp, Vesta};
    use once_cell::sync::Lazy;
    use poly_commitment::{commitment::CommitmentCurve, ipa::SRS};
    use proptest::prelude::*;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(SRS_SIZE)
        }
    });

    static DOMAIN: Lazy<EvaluationDomains<ScalarField>> =
        Lazy::new(|| EvaluationDomains::<ScalarField>::create(SRS_SIZE).unwrap());

    static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
        Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

    fn generate_random_inst_wit<RNG>(rng: &mut RNG) -> (RelaxedInstance, RelaxedWitness)
    where
        RNG: RngCore + CryptoRng,
    {
        let data: Vec<ScalarField> = {
            let mut data = vec![];
            (0..SRS_SIZE).for_each(|_| data.push(Fp::rand(rng)));
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), DOMAIN.d1).interpolate();
        let data_comm: Curve = SRS.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![];
            (0..SRS_SIZE).for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.1)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        let comm_q = SRS
            .commit_non_hiding(
                &Evaluations::from_vec_and_domain(query.clone(), DOMAIN.d1).interpolate(),
                1,
            )
            .chunks[0];

        let comm_a = SRS
            .commit_non_hiding(
                &Evaluations::from_vec_and_domain(answer.clone(), DOMAIN.d1).interpolate(),
                1,
            )
            .chunks[0];

        let relaxed_instance = RelaxedInstance {
            u: ScalarField::one(),
            comm_e: Curve::zero(),
            comm_d: data_comm,
            comm_q,
            comm_a,
        };

        let relaxed_witness = RelaxedWitness {
            e: Evaluations::from_vec_and_domain(vec![ScalarField::zero(); SRS_SIZE], DOMAIN.d1),
            d: Evaluations::from_vec_and_domain(data, DOMAIN.d1),
            q: Evaluations::from_vec_and_domain(query, DOMAIN.d1),
            a: Evaluations::from_vec_and_domain(answer, DOMAIN.d1),
        };

        (relaxed_instance, relaxed_witness)
    }

    #[test]
    fn test_folding_read_proof_completeness_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let (relaxed_instance_1, relaxed_witness_1) = generate_random_inst_wit(&mut rng);
        let (relaxed_instance_2, relaxed_witness_2) = generate_random_inst_wit(&mut rng);

        assert!(relaxed_instance_1.check_in_language(&SRS, &relaxed_witness_1));
        assert!(relaxed_instance_2.check_in_language(&SRS, &relaxed_witness_2));

        let (relaxed_instance_3, relaxed_witness_3, error_term_1) = folding_prover(
            &SRS,
            &relaxed_instance_1,
            &relaxed_instance_2,
            &relaxed_witness_1,
            &relaxed_witness_2,
        );

        assert!(relaxed_instance_3.check_in_language(&SRS, &relaxed_witness_3));

        let relaxed_instance_3_v =
            folding_verifier(&relaxed_instance_1, &relaxed_instance_2, error_term_1);

        assert!(relaxed_instance_3_v == relaxed_instance_3);

        let proof = prove_relaxed(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &relaxed_instance_3,
            &relaxed_witness_3,
        );
        let res = verify_relaxed(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &relaxed_instance_3,
            &proof,
        );

        assert!(res, "Completeness: Proof must verify");

        let proof_malformed_1 = ReadProof {
            quotient_comm: Curve::zero(),
            ..proof.clone()
        };

        let res_1 = verify_relaxed(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &relaxed_instance_3,
            &proof_malformed_1,
        );

        assert!(!res_1, "Soundness: Malformed proof #1 must NOT verify");

        let proof_malformed_2 = ReadProof {
            query_eval: ScalarField::one(),
            ..proof.clone()
        };

        let res_2 = verify_relaxed(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &relaxed_instance_3,
            &proof_malformed_2,
        );

        assert!(!res_2, "Soundness: Malformed proof #2 must NOT verify");
    }
}
