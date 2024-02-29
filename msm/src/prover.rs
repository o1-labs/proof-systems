use ark_ff::Zero;
use ark_poly::Evaluations;
use ark_poly::{univariate::DensePolynomial, Polynomial, Radix2EvaluationDomain as D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use crate::mvlookup::{self, LookupProof};
use crate::proof::{Proof, ProofInputs};
use crate::witness::Witness;

pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
    Column,
    RNG,
    const N: usize,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    inputs: ProofInputs<N, G>,
    _constraints: Vec<Expr<ConstantExpr<G::ScalarField>, Column>>,
    rng: &mut RNG,
) -> Proof<N, G, OpeningProof>
where
    OpeningProof::SRS: Sync,
    RNG: RngCore + CryptoRng,
{
    // Interpolate all columns on d1, using trait Into.
    let evaluations: Witness<N, Evaluations<G::ScalarField, D<G::ScalarField>>> = inputs
        .evaluations
        .into_par_iter()
        .map(|evals| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
        })
        .collect::<Witness<N, Evaluations<G::ScalarField, D<G::ScalarField>>>>();

    let polys: Witness<N, DensePolynomial<G::ScalarField>> = {
        let interpolate =
            |evals: Evaluations<G::ScalarField, D<G::ScalarField>>| evals.interpolate();
        evaluations
            .into_par_iter()
            .map(interpolate)
            .collect::<Witness<N, DensePolynomial<G::ScalarField>>>()
    };

    let commitments: Witness<N, PolyComm<G>> = {
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1);
        (&polys)
            .into_par_iter()
            .map(comm)
            .collect::<Witness<N, PolyComm<G>>>()
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    // Do not use parallelism
    (&commitments)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    // -- Start MVLookup
    let lookup_env = if !inputs.mvlookups.is_empty() {
        Some(mvlookup::prover::Env::create::<OpeningProof, EFqSponge>(
            inputs.mvlookups,
            domain,
            &mut fq_sponge,
            srs,
        ))
    } else {
        None
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
            let Witness { cols: polys } = &polys;
            let mut evals: [G::ScalarField; N] = [G::ScalarField::zero(); N];
            for (i, poly) in polys.iter().enumerate() {
                evals[i] = poly.evaluate(point)
            }
            Witness { cols: evals }
        };
        (evals(&zeta), evals(&zeta_omega))
    };
    let (mvlookup_zeta_evaluations, mvlookup_zeta_omega_evaluations) = {
        if let Some(ref lookup_env) = lookup_env {
            let evals = |point| {
                let eval = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
                let m = (&lookup_env.lookup_counters_poly_d1)
                    .into_par_iter()
                    .map(eval)
                    .collect::<Vec<_>>();
                let h = (&lookup_env.lookup_terms_poly_d1)
                    .into_par_iter()
                    .map(eval)
                    .collect::<Vec<_>>();
                let sum = eval(&lookup_env.lookup_aggregation_poly_d1);
                LookupProof { m, h, sum }
            };
            (Some(evals(&zeta)), Some(evals(&zeta_omega)))
        } else {
            (None, None)
        }
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
                PolyComm {
                    elems: vec![G::ScalarField::zero()],
                },
            )
        })
        .collect();
    // Adding MVLookup
    if let Some(ref lookup_env) = lookup_env {
        // -- first m(X)
        polynomials.extend(
            (&lookup_env.lookup_counters_poly_d1)
                .into_par_iter()
                .map(|poly| {
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(poly),
                        PolyComm {
                            elems: vec![G::ScalarField::zero()],
                        },
                    )
                })
                .collect::<Vec<_>>(),
        );
        // -- after that f_i and t
        polynomials.extend(
            (&lookup_env.lookup_terms_poly_d1)
                .into_par_iter()
                .map(|poly| {
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(poly),
                        PolyComm {
                            elems: vec![G::ScalarField::zero()],
                        },
                    )
                })
                .collect::<Vec<_>>(),
        );
        // -- after that the running sum
        polynomials.push((
            DensePolynomialOrEvaluations::DensePolynomial(&lookup_env.lookup_aggregation_poly_d1),
            PolyComm {
                elems: vec![G::ScalarField::zero()],
            },
        ));
    }

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in (&zeta_evaluations)
        .into_iter()
        .zip((&zeta_omega_evaluations).into_iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    if lookup_env.is_some() {
        // MVLookup FS
        for (zeta_eval, zeta_omega_eval) in
            mvlookup_zeta_evaluations.as_ref().unwrap().into_iter().zip(
                mvlookup_zeta_omega_evaluations
                    .as_ref()
                    .unwrap()
                    .into_iter(),
            )
        {
            fr_sponge.absorb(zeta_eval);
            fr_sponge.absorb(zeta_omega_eval);
        }
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
        rng,
    );
    // -- End opening proof - Preparing the structures

    // FIXME: remove clone
    let mvlookup_commitments = if let Some(lookup_env) = lookup_env {
        Some(LookupProof {
            m: lookup_env.lookup_counters_comm_d1.clone(),
            h: lookup_env.lookup_terms_comms_d1.clone(),
            sum: lookup_env.lookup_aggregation_comm_d1.clone(),
        })
    } else {
        None
    };

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
