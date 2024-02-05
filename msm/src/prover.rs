use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS as _,
};

use crate::NUM_LOOKUP_M;

use crate::mvlookup::{Lookup, LookupProof};
use crate::proof::{Proof, Witness, WitnessColumns};
use std::array;

pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    // a vector of lookups per row
    lookups: Vec<[Vec<Lookup<G::ScalarField>>; NUM_LOOKUP_M]>,
    lookup_counters: Vec<u64>,
    inputs: Witness<G>,
) -> Proof<G, OpeningProof>
where
    OpeningProof::SRS: Sync,
{
    let Witness {
        evaluations: evaluations,
    } = inputs;
    let polys = {
        let WitnessColumns {
            a,
            b,
            c,
            // q,
        } = evaluations;
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        let a = a.into_iter().map(eval_col).collect::<Vec<_>>();
        let b = b.into_iter().map(eval_col).collect::<Vec<_>>();
        let c = c.into_iter().map(eval_col).collect::<Vec<_>>();
        WitnessColumns {
            a: a.try_into().unwrap(),
            b: b.try_into().unwrap(),
            c: c.try_into().unwrap(),
            // q,
        }
    };

    let commitments = {
        let WitnessColumns {
            a,
            b,
            c,
            // q,
        } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1, None);
        let a = a.iter().map(comm).collect::<Vec<_>>();
        let b = b.iter().map(comm).collect::<Vec<_>>();
        let c = c.iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            a: a.try_into().unwrap(),
            b: b.try_into().unwrap(),
            c: c.try_into().unwrap(),
            // q,
        }
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
    for comm in commitments.a.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.b.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.c.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }

    // -- Start MVLookup
    // https://eprint.iacr.org/2022/1530.pdf
    // Polynomial m(X)
    let lookup_counters_poly_d1: DensePolynomial<G::ScalarField> = {
        let lookup_counters = lookup_counters
            .into_iter()
            .map(G::ScalarField::from)
            .collect();
        let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            lookup_counters,
            domain.d1,
        );
        evals.interpolate()
    };
    let lookup_counters_evals_d8: Evaluations<G::ScalarField, D<G::ScalarField>> = {
        // We interpolate and get evaluations on d8 also. TODO: check if required.
        (&lookup_counters_poly_d1).evaluate_over_domain_by_ref(domain.d8)
    };

    let lookup_counters_comm_d1: PolyComm<G> =
        srs.commit_evaluations_non_hiding(domain.d1, &lookup_counters_evals_d8);

    absorb_commitment(&mut fq_sponge, &lookup_counters_comm_d1);
    // -- end of m(X)

    // -- start computing invividual elements of the lookup (f_i and t_i)
    // It will be used to compute the running sum in lookup_aggregation
    let vector_lookup_value_combiner = fq_sponge.challenge();

    let beta = fq_sponge.challenge();

    // TODO: check domain size
    // TODO: we have the table t(x) in the first index, fix it. Split between
    // f_i and t_i. We have also NUM_LOOKUP_M - 1 lookups per row. Use a struct
    // with the trait Iterator implemented.
    let lookup_terms_evals_d1: [Evaluations<G::ScalarField, D<G::ScalarField>>; NUM_LOOKUP_M] =
        array::from_fn(|i| {
            // TODO: check domain size. Why 6?
            let mut denominators = Vec::with_capacity(6 * domain.d1.size as usize);
            for row_lookups in lookups.iter() {
                for Lookup {
                    numerator: _,
                    table_id,
                    value,
                } in row_lookups[i].iter()
                {
                    // x + r * y + r^2 * z + ... + r^n table_id
                    let combined_value = value.iter().rev().fold(G::ScalarField::zero(), |x, y| {
                        x * vector_lookup_value_combiner + y
                    }) * vector_lookup_value_combiner
                        + G::ScalarField::from(*table_id as u64);

                    // beta + a_{i}
                    let lookup_denominator = beta + combined_value;
                    denominators.push(lookup_denominator);
                }
            }

            ark_ff::fields::batch_inversion(&mut denominators);

            let mut evals = Vec::with_capacity(domain.d1.size as usize);
            let mut denominator_index = 0;

            for row_lookups in lookups.iter() {
                let mut row_acc = G::ScalarField::zero();
                for Lookup {
                    numerator,
                    table_id: _,
                    value: _,
                } in row_lookups[i].iter()
                {
                    row_acc += *numerator * denominators[denominator_index];
                    denominator_index += 1;
                }
                evals.push(row_acc)
            }
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
        });

    let lookup_terms_poly_d1: Vec<DensePolynomial<G::ScalarField>> = lookup_terms_evals_d1
        .into_iter()
        .map(|evals| evals.interpolate_by_ref())
        .collect();

    // We evaluate on d8 also. TODO: check if required.
    let lookup_terms_evals_d8: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
        lookup_terms_poly_d1
            .iter()
            .map(|p| (&p).evaluate_over_domain_by_ref(domain.d8))
            .collect();

    let lookup_terms_comms_d1: Vec<PolyComm<G>> = lookup_terms_evals_d8
        .clone()
        .into_iter()
        .map(|lt| srs.commit_evaluations_non_hiding(domain.d1, &lt))
        .collect();

    for comm in lookup_terms_comms_d1.iter() {
        absorb_commitment(&mut fq_sponge, comm);
    }
    // -- end computing invividual elements of the lookup (f_i and t_i)

    // -- start computing the running sum in lookup_aggregation
    let lookup_aggregation_evals_d1 = {
        let mut evals = Vec::with_capacity(domain.d1.size as usize);
        let mut acc = G::ScalarField::zero();
        for i in 0..domain.d1.size as usize {
            // phi(1) = 0
            evals.push(acc);
            // Terms are f_1, ..., f_n, t
            for terms in lookup_terms_evals_d8.iter() {
                // Because the individual evaluations of f_i and t are on d1
                acc += terms[8 * i];
            }
        }
        assert_eq!(acc, G::ScalarField::zero());
        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
    };
    let lookup_aggregation_poly_d1 = lookup_aggregation_evals_d1.interpolate();
    // We evaluate on d8 also. TODO: check if required.
    let lookup_aggregation_evals_d8 =
        (&lookup_aggregation_poly_d1).evaluate_over_domain_by_ref(domain.d8);

    let lookup_aggregation_comm_d1 =
        srs.commit_evaluations_non_hiding(domain.d1, &lookup_aggregation_evals_d8);

    absorb_commitment(&mut fq_sponge, &lookup_aggregation_comm_d1);

    let mvlookup_commitment = LookupProof {
        m: lookup_counters_comm_d1,
        f: lookup_terms_comms_d1,
        sum: lookup_aggregation_comm_d1,
    };
    // -- end computing the running sum in lookup_aggregation

    // -- End of MVLookup

    // TODO: add quotient polynomial (based on constraints and expresion framework)

    // We start the evaluations.
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    // Evaluate the polynomials at zeta and zeta * omega -- Columns
    let (zeta_evaluations, zeta_omega_evaluations) = {
        let evals = |point| {
            let WitnessColumns { a, b, c } = &polys;
            let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
            let a = a.iter().map(comm).collect::<Vec<_>>();
            let b = b.iter().map(comm).collect::<Vec<_>>();
            let c = c.iter().map(comm).collect::<Vec<_>>();
            WitnessColumns {
                a: a.try_into().unwrap(),
                b: b.try_into().unwrap(),
                c: c.try_into().unwrap(),
            }
        };
        (evals(&zeta), evals(&zeta_omega))
    };
    // Lookup polynomials
    let mvlookup_zeta_evaluations: LookupProof<G::ScalarField> = LookupProof {
        m: lookup_counters_poly_d1.evaluate(&zeta),
        f: lookup_terms_poly_d1
            .iter()
            .map(|terms| (&terms).evaluate(&zeta))
            .collect::<Vec<_>>(),
        sum: lookup_aggregation_poly_d1.evaluate(&zeta),
    };
    let mvlookup_zeta_omega_evaluations = LookupProof {
        m: lookup_counters_poly_d1.evaluate(&zeta_omega),
        f: lookup_terms_poly_d1
            .iter()
            .map(|terms| (&terms).evaluate(&zeta_omega))
            .collect::<Vec<_>>(),
        sum: lookup_aggregation_poly_d1.evaluate(&zeta_omega),
    };

    // -- Start opening proof - Preparing the Rust structures
    let group_map = G::Map::setup();

    // Gathering all polynomials
    let mut polynomials: Vec<DensePolynomial<_>> = polys.a.into_iter().collect();
    polynomials.extend(polys.b.into_iter().collect::<Vec<_>>());
    polynomials.extend(polys.c.into_iter().collect::<Vec<_>>());
    // TODO: add lookup fs
    // TODO: add lookup t
    // TODO: add lookup sum

    let polynomials: Vec<_> = polynomials
        .iter()
        .map(|poly| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(poly),
                None,
                PolyComm {
                    unshifted: vec![G::ScalarField::zero()],
                    shifted: None,
                },
            )
        })
        .collect();

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .a
        .iter()
        .zip(zeta_omega_evaluations.a.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .b
        .iter()
        .zip(zeta_omega_evaluations.b.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .c
        .iter()
        .zip(zeta_omega_evaluations.c.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    // MVLookup absorb evaluations
    // First evaluations of m, after that f and finisshing with sum
    fr_sponge.absorb(&mvlookup_zeta_evaluations.m);
    fr_sponge.absorb(&mvlookup_zeta_omega_evaluations.m);
    for (zeta_eval, zeta_omega_eval) in mvlookup_zeta_evaluations
        .f
        .iter()
        .zip(mvlookup_zeta_omega_evaluations.f.iter())
    {
        fr_sponge.absorb(&zeta_eval);
        fr_sponge.absorb(&zeta_omega_eval);
    }
    fr_sponge.absorb(&mvlookup_zeta_evaluations.sum);
    fr_sponge.absorb(&mvlookup_zeta_omega_evaluations.sum);

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let opening_proof = OpenProof::open::<_, _, D<G::ScalarField>>(
        srs,
        &group_map,
        polynomials.as_slice(),
        &[zeta, zeta_omega],
        v,
        u,
        fq_sponge_before_evaluations,
        &mut rand::rngs::OsRng,
    );
    // -- End opening proof - Preparing the structures

    Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
        lookup_commitments: mvlookup_commitment,
        lookup_zeta_evaluations: mvlookup_zeta_evaluations,
        lookup_zeta_omega_evaluations: mvlookup_zeta_omega_evaluations,
    }
}
