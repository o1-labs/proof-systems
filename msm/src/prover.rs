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

use crate::lookup::Lookup;
use crate::proof::{LookupProof, Proof, Witness, WitnessColumns};
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
    let Witness { evaluations } = inputs;
    // Computate the polynomial coefficients from the evaluations using interpolation
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
    // Commit to the polynomials
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

    // Start of MVLookup
    // Lookup counters, computing the number of lookups per row
    // ---
    // Polynomial m(X), domain D1
    let lookup_counters = lookup_counters
        .into_iter()
        .map(G::ScalarField::from)
        .collect();
    let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
        lookup_counters,
        domain.d1,
    );
    let evals = evals.interpolate().evaluate_over_domain(domain.d1);

    let lookup_counters_comm = srs.commit_evaluations_non_hiding(domain.d1, &evals);

    absorb_commitment(&mut fq_sponge, &lookup_counters_comm);

    // Combiner for denominator
    let vector_lookup_value_combiner = fq_sponge.challenge();

    // Random point for evaluation
    let beta = fq_sponge.challenge();

    // We will now compute the f_{i}(X)
    // https://github.com/Orbis-Tertius/MVlookups/blob/main/MVlookup.pdf
    // (12) - page 9
    // we use a batch inversion optimisation. Computing first the denominator
    // and inverting it in batch, and after that multiplying by the numerator
    // TODO: we do a lookup on the 16 results
    let lookup_terms: [Evaluations<G::ScalarField, D<G::ScalarField>>; NUM_LOOKUP_M] =
        array::from_fn(|i| {
            // is 6 * domain size not sure why
            let mut denominators = Vec::with_capacity(6 * domain.d1.size as usize);
            for row_lookups in lookups.iter() {
                // First computing the denominators
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

            // numerator
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
            //
            let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                evals, domain.d1,
            );
            // why 8?
            evals.interpolate().evaluate_over_domain(domain.d8)
        });

    // Compute commitments to f_{i}(X)
    let lookup_terms_comms: [PolyComm<G>; NUM_LOOKUP_M] =
        array::from_fn(|i| srs.commit_evaluations_non_hiding(domain.d1, &lookup_terms[i]));

    for comm in lookup_terms_comms.iter() {
        absorb_commitment(&mut fq_sponge, comm);
    }

    // Lookup aggregation
    // Sum of f_{i}
    let lookup_aggregation = {
        let mut evals = Vec::with_capacity(domain.d1.size as usize);
        let mut acc = G::ScalarField::zero();
        // Accumulate lookup terms
        for i in 0..domain.d1.size as usize {
            evals.push(acc);
            for terms in lookup_terms.iter() {
                acc += terms[8 * i];
            }
        }
        assert_eq!(acc, G::ScalarField::zero());
        let evals =
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1);
        evals.interpolate().evaluate_over_domain(domain.d1)
    };

    let lookup_aggregation_comm = srs.commit_evaluations_non_hiding(domain.d1, &lookup_aggregation);

    absorb_commitment(&mut fq_sponge, &lookup_aggregation_comm);

    // End of MVLookup

    // We start the evaluations.

    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    // Evaluate the polynomials at zeta and zeta * omega
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
    let zeta_evaluations = evals(&zeta);
    let zeta_omega_evaluations = evals(&zeta_omega);

    let group_map = G::Map::setup();
    // TODO make mut
    let polynomials: Vec<_> = polys.a.into_iter().collect();
    // TODO: add B and C
    // TODO: lookups

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
    // TODO: add B and C
    // TODO: lookup

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

    Proof {
        commitments,
        lookup_commitments: LookupProof {
            lookup_counter: lookup_counters_comm,
            lookup_terms: lookup_terms_comms,
            lookup_aggregation: lookup_aggregation_comm,
        },
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    }
}
