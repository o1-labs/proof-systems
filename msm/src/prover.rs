use ark_ff::Zero;
use ark_poly::Evaluations;
use ark_poly::{univariate::DensePolynomial, Polynomial, Radix2EvaluationDomain as D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS,
};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use crate::mvlookup::{Lookup, LookupProof, LookupWitness};
use crate::proof::{Proof, Witness, WitnessColumns};

pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    inputs: Witness<G>,
) -> Proof<G, OpeningProof>
where
    OpeningProof::SRS: Sync,
{
    // Interpolate all columns on d1, using trait Into.
    let polys: WitnessColumns<DensePolynomial<G::ScalarField>> = {
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        inputs
            .evaluations
            .into_par_iter()
            .map(eval_col)
            .collect::<WitnessColumns<_>>()
    };

    let commitments: WitnessColumns<PolyComm<G>> = {
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1, None);
        (&polys)
            .into_par_iter()
            .map(comm)
            .collect::<WitnessColumns<_>>()
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    // Do not use parallelism
    commitments
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    // -- Start MVLookup
    // TODO: handle more than one, use into_parallel
    assert_eq!(inputs.mvlookups.len(), 1);
    let mvlookup: &LookupWitness<G::ScalarField> = &inputs.mvlookups[0];
    let LookupWitness { f, t, m } = mvlookup;

    // Polynomial m(X)
    let lookup_counters_poly_d1: DensePolynomial<G::ScalarField> = {
        let evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            m.to_vec(),
            domain.d1,
        );
        evals.interpolate()
    };
    let lookup_counters_evals_d8: Evaluations<G::ScalarField, D<G::ScalarField>> = {
        // We interpolate and get evaluations on d8 also
        lookup_counters_poly_d1.evaluate_over_domain_by_ref(domain.d8)
    };

    let lookup_counters_comm_d1: PolyComm<G> =
        srs.commit_evaluations_non_hiding(domain.d1, &lookup_counters_evals_d8);

    absorb_commitment(&mut fq_sponge, &lookup_counters_comm_d1);
    // -- end of m(X)

    // -- start computing individual elements of the lookup (f_i and t)
    // It will be used to compute the running sum in lookup_aggregation
    // Coin a combiner to perform vector lookup.
    let vector_lookup_value_combiner = fq_sponge.challenge();

    // Coin an evaluation point for the rational functions
    let beta = fq_sponge.challenge();

    let n = f.len();
    let lookup_terms_evals: Vec<G::ScalarField> = {
        // We compute first the denominators of all f_i and t. We gather them in
        // a vector to perform a batch inversion.
        // We include t in the denominator, therefore n + 1
        let mut denominators = Vec::with_capacity((n + 1) * domain.d1.size as usize);
        // Iterate over the rows
        for f_i in f.iter() {
            // Iterate over individual columns (i.e. f_i and t)
            for Lookup {
                numerator: _,
                table_id,
                value,
            } in f_i.iter().chain(t.iter())
            // Include t
            {
                // x + r * y + r^2 * z + ... + r^n table_id
                let combined_value: G::ScalarField =
                    value.iter().rev().fold(G::ScalarField::zero(), |x, y| {
                        x * vector_lookup_value_combiner + y
                    }) * vector_lookup_value_combiner
                        + table_id.into_field::<G::ScalarField>();

                // beta + a_{i}
                let lookup_denominator = beta + combined_value;
                denominators.push(lookup_denominator);
            }
        }

        ark_ff::fields::batch_inversion(&mut denominators);

        // n + 1 for t
        let mut evals = Vec::with_capacity((n + 1) * domain.d1.size as usize);
        let mut denominator_index = 0;

        // Including now the numerator
        for row_lookups in f.iter() {
            let mut row_acc = G::ScalarField::zero();
            for Lookup {
                numerator,
                table_id: _,
                value: _,
            } in row_lookups.iter().chain(t.iter())
            {
                row_acc += *numerator * denominators[denominator_index];
                denominator_index += 1;
            }
            evals.push(row_acc)
        }
        evals
    };

    // evals contain the evaluations for the N + 1 polynomials. We must split it
    // in individual vectors to interpolate and commit.
    // Get back the individual evaluation f_i and t
    let mut individual_evals: Vec<Vec<G::ScalarField>> = Vec::with_capacity(n + 1);
    for _i in 0..=n {
        individual_evals.push(Vec::with_capacity(domain.d1.size as usize));
    }

    for (i, v) in lookup_terms_evals.iter().enumerate() {
        individual_evals[i % (n + 1)].push(*v)
    }

    let lookup_terms_evals_d1: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
        individual_evals
            // Parallelize
            .into_par_iter()
            .map(|evals| {
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals, domain.d1,
                )
            })
            .collect();

    let lookup_terms_poly_d1: Vec<DensePolynomial<G::ScalarField>> = (&lookup_terms_evals_d1)
        // Parallelize
        .into_par_iter()
        .map(|evals| evals.interpolate_by_ref())
        .collect();

    let lookup_terms_evals_d8: Vec<Evaluations<G::ScalarField, D<G::ScalarField>>> =
        (&lookup_terms_poly_d1)
            // Parallelize
            .into_par_iter()
            .map(|p| p.evaluate_over_domain_by_ref(domain.d8))
            .collect();

    let lookup_terms_comms_d1: Vec<PolyComm<G>> = (&lookup_terms_evals_d8)
        // Parallelize
        .into_par_iter()
        .map(|lt| srs.commit_evaluations_non_hiding(domain.d1, lt))
        .collect();

    lookup_terms_comms_d1
        .iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));
    // -- end computing individual elements of the lookup (f_i and t)

    // -- start computing the running sum in lookup_aggregation
    // The running sum, \phi, is defined recursively over the subgroup as followed:
    // - phi(1) = 0
    // - phi(\omega^{j + 1}) = \phi(\omega^j) + \
    //                         \sum_{i = 1}^{n} (1 / \beta + f_i(\omega^{j + 1})) - \
    //                         (m(\omega^{j + 1}) / beta + t(\omega^{j + 1}))
    // - phi(\omega^n) = 0
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
        // Sanity check to verify that the accumulator ends up being zero.
        assert_eq!(acc, G::ScalarField::zero());
        Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
    };

    let lookup_aggregation_poly_d1 = lookup_aggregation_evals_d1.interpolate();
    let lookup_aggregation_evals_d8 =
        lookup_aggregation_poly_d1.evaluate_over_domain_by_ref(domain.d8);

    let lookup_aggregation_comm_d1 =
        srs.commit_evaluations_non_hiding(domain.d1, &lookup_aggregation_evals_d8);

    absorb_commitment(&mut fq_sponge, &lookup_aggregation_comm_d1);

    let mvlookup_commitments = LookupProof {
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
    // TODO: Parallelize
    let (zeta_evaluations, zeta_omega_evaluations) = {
        let evals = |point| {
            let WitnessColumns { x } = &polys;
            let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
            let x = x.iter().map(comm).collect::<Vec<_>>();
            WitnessColumns { x }
        };
        (evals(&zeta), evals(&zeta_omega))
    };
    // TODO: Parallelize
    let (mvlookup_zeta_evaluations, mvlookup_zeta_omega_evaluations) = {
        let evals = |point| {
            let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
            let m = comm(&lookup_counters_poly_d1);
            let f = lookup_terms_poly_d1.iter().map(comm).collect::<Vec<_>>();
            let sum = comm(&lookup_aggregation_poly_d1);
            LookupProof { m, f, sum }
        };
        (evals(&zeta), evals(&zeta_omega))
    };
    // -- Start opening proof - Preparing the Rust structures
    let group_map = G::Map::setup();

    // Gathering all polynomials to use in the opening proof
    let polynomials: Vec<_> = polys.into_iter().collect();

    let mut polynomials: Vec<_> = polynomials
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
    // Adding MVLookup
    // -- first m(X)
    polynomials.push((
        DensePolynomialOrEvaluations::DensePolynomial(&lookup_counters_poly_d1),
        None,
        PolyComm {
            unshifted: vec![G::ScalarField::zero()],
            shifted: None,
        },
    ));
    // -- after that f_i and t
    polynomials.extend(
        lookup_terms_poly_d1
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
            .collect::<Vec<_>>(),
    );
    // -- after that the running sum
    polynomials.push((
        DensePolynomialOrEvaluations::DensePolynomial(&lookup_aggregation_poly_d1),
        None,
        PolyComm {
            unshifted: vec![G::ScalarField::zero()],
            shifted: None,
        },
    ));

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .into_iter()
        .zip(zeta_omega_evaluations.into_iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    // MVLookup FS
    for (zeta_eval, zeta_omega_eval) in mvlookup_zeta_evaluations
        .into_iter()
        .zip(mvlookup_zeta_omega_evaluations.into_iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }

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
        mvlookup_commitments,
        mvlookup_zeta_evaluations,
        mvlookup_zeta_omega_evaluations,
        opening_proof,
    }
}
