//! Folding version of the read prover.
//!
//! The main gist of the protocol is to run a trivial sangria-like
//! folding without recursive circuit (non-IVC variant),
//! interactively, between the prover and the verifier.
//!
//! The original equation we want to prove is `d(X) * q(X) - a(X) = 0`.
//!
//! After homogenization it becomes `d(X) * q(X) - a(X) * u - e(X) =
//! 0` where u is a homogenization factor (field element), and `e(X)`
//! is an error polynomial.
//!
//! During the folding procedure we fold one non-relaxed instance with
//! a relaxed instance (number 1 and 2 correspondingly), and the
//! result of this is a relaxed instance. The recombination
//! coefficient `r` is sampled as usual, using Fiat-Shamir, and then
//! we recombine vectors and commitments as follows:
//!
//! `a_3(X) <- a_1(X) + r * a_2(X)` (same for `d, q`)
//!
//! To compute the new error term, we have to use the formula
//!
//! `e_3(X) <- r * cross_term(X) + r^2 * e_2(X)`
//!
//! where `cross_term(X) := a_2 + u_2 * a_1 - q_2 * d_1 - q_1 * d_2`.
//!
//! Finally, in this file we provide a prover and verifier attesting
//! to the validity of a relaxed instance using plonk-like protocol
//! with IPA.
//!
//! For mor details see the full version of the protocol in the whitepaper.

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
/// Non-relaxed instance attesting to `d * q - a = 0`
pub struct CoreInstance {
    /// Commitment to the data
    pub comm_d: Curve,
    /// Commitment to the query polynomial
    pub comm_q: Curve,
    /// Commitment to the answers
    pub comm_a: Curve,
}

#[derive(PartialEq, Eq)]
/// Relaxed instance variant, attesting to `d * q - a * u - e = 0`
pub struct RelaxedInstance {
    /// Non-relaxed part
    pub core: CoreInstance,
    /// Homogeneization term for folding
    pub u: ScalarField,
    /// Commitment to the error term for folding
    pub comm_e: Curve,
}

impl CoreInstance {
    pub fn relax(self) -> RelaxedInstance {
        RelaxedInstance {
            core: self,
            u: ScalarField::one(),
            comm_e: Curve::zero(),
        }
    }
}

#[derive(PartialEq, Eq)]
/// Non-relaxed witness contains evaluations (field vectors) for data,
/// query, and answers.
pub struct CoreWitness {
    pub d: Evaluations<ScalarField, R2D<ScalarField>>,
    pub q: Evaluations<ScalarField, R2D<ScalarField>>,
    pub a: Evaluations<ScalarField, R2D<ScalarField>>,
}

#[derive(PartialEq, Eq)]
/// Relaxed witness extends the non-relaxed witness with evaluations
/// of the error term.
pub struct RelaxedWitness {
    pub core: CoreWitness,
    pub e: Evaluations<ScalarField, R2D<ScalarField>>,
}

impl CoreWitness {
    pub fn relax(self, domain: R2D<ScalarField>) -> RelaxedWitness {
        RelaxedWitness {
            core: self,
            e: Evaluations::from_vec_and_domain(vec![ScalarField::zero(); domain.size()], domain),
        }
    }
}

impl RelaxedInstance {
    /// This function checks if the provided instance is valid regarding the
    /// provided witness, by checking both the validity of the witness and its
    /// consistency with the instance's commitments.
    pub fn check_in_language(
        &self,
        srs: &SRS<Curve>,
        domain: R2D<ScalarField>,
        wit: &RelaxedWitness,
    ) -> bool {
        for i in 0..SRS_SIZE {
            // todo can be parallelized
            if self.u * wit.core.a[i] - wit.core.q[i] * wit.core.d[i] + wit.e[i]
                != ScalarField::zero()
            {
                return false;
            }
        }
        if self.core.comm_a
            != srs
                .commit_evaluations_non_hiding(domain, &wit.core.a)
                .chunks[0]
        {
            return false;
        }
        if self.core.comm_d
            != srs
                .commit_evaluations_non_hiding(domain, &wit.core.d)
                .chunks[0]
        {
            return false;
        }
        if self.core.comm_q
            != srs
                .commit_evaluations_non_hiding(domain, &wit.core.q)
                .chunks[0]
        {
            return false;
        }
        if self.comm_e != srs.commit_evaluations_non_hiding(domain, &wit.e).chunks[0] {
            return false;
        }
        true
    }
}

pub fn folding_prover(
    srs: &SRS<Curve>,
    domain: R2D<ScalarField>,
    inst1: &CoreInstance,
    wit1: &CoreWitness,
    inst2: &RelaxedInstance,
    wit2: &RelaxedWitness,
) -> (RelaxedInstance, RelaxedWitness, Curve) {
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let cross_term: Evaluations<ScalarField, R2D<ScalarField>> =
        &(&(&wit2.core.a + &(&wit1.a * inst2.u)) - &(&wit2.core.q * &wit1.d))
            - &(&wit1.q * &wit2.core.d);

    let cross_term_comm: Curve = srs
        .commit_evaluations_non_hiding(domain, &cross_term.clone())
        .chunks[0];

    fq_sponge.absorb_g(&[
        inst1.comm_d,
        inst1.comm_q,
        inst1.comm_a,
        inst2.core.comm_d,
        inst2.core.comm_q,
        inst2.core.comm_a,
        inst2.comm_e,
        cross_term_comm,
    ]);

    let recombination_chal = fq_sponge.challenge();

    let a3 = &wit1.a + &(&wit2.core.a * recombination_chal);
    let q3 = &wit1.q + &(&wit2.core.q * recombination_chal);
    let d3 = &wit1.d + &(&wit2.core.d * recombination_chal);

    let comm_a3 = inst1.comm_a + inst2.core.comm_a * recombination_chal;
    let comm_q3 = inst1.comm_q + inst2.core.comm_q * recombination_chal;
    let comm_d3 = inst1.comm_d + inst2.core.comm_d * recombination_chal;

    let new_u = ScalarField::one() + recombination_chal * inst2.u;

    let e3 = &(&wit2.e * (recombination_chal * recombination_chal))
        - &(&cross_term * recombination_chal);
    let comm_e3 = inst2.comm_e * (recombination_chal * recombination_chal)
        - cross_term_comm * recombination_chal;

    let new_inst = RelaxedInstance {
        u: new_u,
        comm_e: comm_e3.into(),
        core: CoreInstance {
            comm_d: comm_d3.into(),
            comm_q: comm_q3.into(),
            comm_a: comm_a3.into(),
        },
    };

    let new_wit = RelaxedWitness {
        e: e3,
        core: CoreWitness {
            d: d3,
            q: q3,
            a: a3,
        },
    };

    (new_inst, new_wit, cross_term_comm)
}

pub fn folding_verifier(
    inst1: &CoreInstance,
    inst2: &RelaxedInstance,
    cross_term_comm: Curve,
) -> RelaxedInstance {
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[
        inst1.comm_d,
        inst1.comm_q,
        inst1.comm_a,
        inst2.core.comm_d,
        inst2.core.comm_q,
        inst2.core.comm_a,
        inst2.comm_e,
        cross_term_comm,
    ]);

    let recombination_chal = fq_sponge.challenge();

    let comm_a3 = inst1.comm_a + inst2.core.comm_a * recombination_chal;
    let comm_q3 = inst1.comm_q + inst2.core.comm_q * recombination_chal;
    let comm_d3 = inst1.comm_d + inst2.core.comm_d * recombination_chal;

    let new_u = ScalarField::one() + recombination_chal * inst2.u;

    let comm_e3 = inst2.comm_e * (recombination_chal * recombination_chal)
        - cross_term_comm * recombination_chal;

    RelaxedInstance {
        u: new_u,
        comm_e: comm_e3.into(),
        core: CoreInstance {
            comm_d: comm_d3.into(),
            comm_q: comm_q3.into(),
            comm_a: comm_a3.into(),
        },
    }
}

#[derive(Debug, Clone)]
/// The proof attesting to the validity of the relaxed instance.
pub struct ReadProof {
    /// Commitment of quotient polynomial T (aka t_comm)
    pub quotient_comm: Curve,

    /// Evaluation of data polynomial at the required challenge point
    pub data_eval: ScalarField,
    /// Evaluation of query polynomial at the required challenge point
    pub query_eval: ScalarField,
    /// Evaluation of answer polynomial at the required challenge point
    pub answer_eval: ScalarField,
    /// Evaluation of error polynomial at the required challenge point
    pub error_eval: ScalarField,

    /// Polynomial commitment’s proof for the validity of returned evaluations
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

    let data_poly: DensePolynomial<ScalarField> = wit.core.d.interpolate_by_ref();
    let query_poly: DensePolynomial<ScalarField> = wit.core.q.interpolate_by_ref();
    let answer_poly: DensePolynomial<ScalarField> = wit.core.a.interpolate_by_ref();
    let error_poly: DensePolynomial<ScalarField> = wit.e.interpolate_by_ref();

    fq_sponge.absorb_g(&[
        inst.core.comm_d,
        inst.core.comm_q,
        inst.core.comm_a,
        inst.comm_e,
    ]);

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
        let (quotient, res) = numerator_eval_interpolated.divide_by_vanishing_poly(domain.d1);
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
    fq_sponge.absorb_g(&[
        inst.core.comm_d,
        inst.core.comm_q,
        inst.core.comm_a,
        inst.comm_e,
    ]);
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
                chunks: vec![inst.core.comm_d],
            },
            evaluations: vec![vec![proof.data_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.core.comm_q],
            },
            evaluations: vec![vec![proof.query_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![inst.core.comm_a],
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

pub mod testing {
    use super::*;
    use crate::{Curve, ScalarField};
    use ark_ff::UniformRand;
    use ark_poly::Evaluations;
    use poly_commitment::ipa::SRS;
    use rand::Rng;

    /// Generates a random core instance and witness
    pub fn generate_random_inst_wit_core<RNG>(
        srs: &SRS<Curve>,
        domain: R2D<ScalarField>,
        rng: &mut RNG,
    ) -> (CoreInstance, CoreWitness)
    where
        RNG: RngCore + CryptoRng,
    {
        let data: Vec<ScalarField> = {
            let mut data = vec![];
            (0..domain.size).for_each(|_| data.push(ScalarField::rand(rng)));
            data
        };

        let data_comm: Curve = srs
            .commit_evaluations_non_hiding(
                domain,
                &Evaluations::from_vec_and_domain(data.clone(), domain),
            )
            .chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![];
            (0..domain.size)
                .for_each(|_| query.push(ScalarField::from(rand::thread_rng().gen::<f64>() < 0.1)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        let comm_q = srs
            .commit_evaluations_non_hiding(
                domain,
                &Evaluations::from_vec_and_domain(query.clone(), domain),
            )
            .chunks[0];

        let comm_a = srs
            .commit_evaluations_non_hiding(
                domain,
                &Evaluations::from_vec_and_domain(answer.clone(), domain),
            )
            .chunks[0];

        let core_instance = CoreInstance {
            comm_d: data_comm,
            comm_q,
            comm_a,
        };

        let core_witness = CoreWitness {
            d: Evaluations::from_vec_and_domain(data, domain),
            q: Evaluations::from_vec_and_domain(query, domain),
            a: Evaluations::from_vec_and_domain(answer, domain),
        };

        (core_instance, core_witness)
    }

    /// Generates a relaxed instance and witness. Note that the result
    /// of this function is _not_ an instance-witness pair produced by
    /// a valid folding procedure, but just a generic relaxed pair instead.
    pub fn generate_random_inst_wit_relaxed<RNG>(
        srs: &SRS<Curve>,
        domain: R2D<ScalarField>,
        rng: &mut RNG,
    ) -> (RelaxedInstance, RelaxedWitness)
    where
        RNG: RngCore + CryptoRng,
    {
        let (inst, wit) = generate_random_inst_wit_core(srs, domain, rng);
        let u = ScalarField::rand(rng);
        let e = &(&wit.d * &wit.q) - &(&wit.a * u);
        let comm_e = srs.commit_evaluations_non_hiding(domain, &e).chunks[0];

        let relaxed_instance = RelaxedInstance {
            core: inst,
            u,
            comm_e,
        };

        let relaxed_witness = RelaxedWitness { core: wit, e };

        assert!(relaxed_instance.check_in_language(srs, domain, &relaxed_witness));

        (relaxed_instance, relaxed_witness)
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::generate_random_inst_wit_core, *};
    use crate::{Curve, ScalarField};
    use ark_ec::AffineRepr;
    use ark_ff::One;
    use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
    use poly_commitment::commitment::CommitmentCurve;

    #[test]
    fn test_folding_read_proof_completeness_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let srs = poly_commitment::precomputed_srs::get_srs_test();
        let domain: EvaluationDomains<ScalarField> =
            EvaluationDomains::<ScalarField>::create(srs.size()).unwrap();

        let group_map = <Curve as CommitmentCurve>::Map::setup();

        let (core_instance_1, core_witness_1) =
            generate_random_inst_wit_core(&srs, domain.d1, &mut rng);
        let (core_instance_2, core_witness_2) =
            generate_random_inst_wit_core(&srs, domain.d1, &mut rng);
        let relaxed_instance_2 = core_instance_2.relax();
        let relaxed_witness_2 = core_witness_2.relax(domain.d1);

        assert!(relaxed_instance_2.check_in_language(&srs, domain.d1, &relaxed_witness_2));

        let (relaxed_instance_3, relaxed_witness_3, cross_term_1) = folding_prover(
            &srs,
            domain.d1,
            &core_instance_1,
            &core_witness_1,
            &relaxed_instance_2,
            &relaxed_witness_2,
        );

        assert!(relaxed_instance_3.check_in_language(&srs, domain.d1, &relaxed_witness_3));

        assert!(
            folding_verifier(&core_instance_1, &relaxed_instance_2, cross_term_1)
                == relaxed_instance_3
        );

        let (core_instance_4, core_witness_4) =
            generate_random_inst_wit_core(&srs, domain.d1, &mut rng);
        let (relaxed_instance_5, relaxed_witness_5, cross_term_2) = folding_prover(
            &srs,
            domain.d1,
            &core_instance_4,
            &core_witness_4,
            &relaxed_instance_3,
            &relaxed_witness_3,
        );

        assert!(relaxed_instance_5.check_in_language(&srs, domain.d1, &relaxed_witness_5));

        assert!(
            folding_verifier(&core_instance_4, &relaxed_instance_3, cross_term_2)
                == relaxed_instance_5
        );

        let proof = prove_relaxed(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &relaxed_instance_5,
            &relaxed_witness_5,
        );
        let res = verify_relaxed(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &relaxed_instance_5,
            &proof,
        );

        assert!(res, "Completeness: Proof must verify");

        let proof_malformed_1 = ReadProof {
            quotient_comm: Curve::zero(),
            ..proof.clone()
        };

        let res_1 = verify_relaxed(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &relaxed_instance_5,
            &proof_malformed_1,
        );

        assert!(!res_1, "Soundness: Malformed proof #1 must NOT verify");

        let proof_malformed_2 = ReadProof {
            query_eval: ScalarField::one(),
            ..proof.clone()
        };

        let res_2 = verify_relaxed(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &relaxed_instance_5,
            &proof_malformed_2,
        );

        assert!(!res_2, "Soundness: Malformed proof #2 must NOT verify");
    }
}
