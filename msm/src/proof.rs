use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::plonk_sponge::FrSponge;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{
        absorb_commitment, combined_inner_product, BatchEvaluationProof, Evaluation, PolyComm,
    },
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS as _,
};
use rand::thread_rng;

use crate::{DOMAIN_SIZE, NUM_LIMBS};


#[derive(Debug)]
pub struct WitnessColumns<G> {
    pub a: [G; NUM_LIMBS],
    pub b: [G; NUM_LIMBS],
    pub c: [G; NUM_LIMBS],
}

#[derive(Debug)]
pub struct ProofInputs<G: KimchiCurve> {
    evaluations: WitnessColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for ProofInputs<G> {
    fn default() -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                a: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                b: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
                c: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::zero()).collect()
                }),
            },
        }
    }
}


#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    commitments: WitnessColumns<PolyComm<G>>,
    zeta_evaluations: WitnessColumns<G::ScalarField>,
    zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    opening_proof: OpeningProof,
}


pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    inputs: ProofInputs<G>,
) -> Proof<G, OpeningProof>
where
    OpeningProof::SRS: Sync,
{
    let ProofInputs { evaluations } = inputs;
    let polys = {
        let WitnessColumns {
            a,
            b,
            c,
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
        }
    };
    let commitments = {
        let WitnessColumns {
            a,
            b,
            c,
        } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1, None);
        let a = a.into_iter().map(comm).collect::<Vec<_>>();
        let b = b.into_iter().map(comm).collect::<Vec<_>>();
        let c = c.into_iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            a: a.try_into().unwrap(),
            b: b.try_into().unwrap(),
            c: c.try_into().unwrap(),
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
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let evals = |point| {
        let WitnessColumns {
            a,
            b,
            c,
        } = &polys;
        let comm = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
        let a = a.into_iter().map(comm).collect::<Vec<_>>();
        let b = b.into_iter().map(comm).collect::<Vec<_>>();
        let c = c.into_iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            a: a.try_into().unwrap(),
            b: b.try_into().unwrap(),
            c: c.try_into().unwrap(),
        }
    };
    let zeta_evaluations = evals(&zeta);
    let zeta_omega_evaluations = evals(&zeta_omega);
    let group_map = G::Map::setup();
    let mut polynomials: Vec<_> = polys.a.into_iter().collect();
    // TODO: add B and C
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
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    }
}

pub fn verify<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    proof: &Proof<G, OpeningProof>,
) -> bool {
    let Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    } = proof;

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
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();
    let zeta: G::ScalarField = zeta_chal.to_field(endo_r);
    let omega = domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let mut es: Vec<_> = zeta_evaluations
        .a
        .iter()
        .zip(zeta_omega_evaluations.a.iter())
        .map(|(zeta, zeta_omega)| (vec![vec![*zeta], vec![*zeta_omega]], None))
        .collect();
    // TODO: add B and C

    let mut evaluations: Vec<_> = commitments
        .a
        .iter()
        .zip(
            zeta_evaluations
                .a
                .iter()
                .zip(zeta_omega_evaluations.a.iter()),
        )
        .map(|(commitment, (zeta_eval, zeta_omega_eval))| Evaluation {
            commitment: commitment.clone(),
            evaluations: vec![vec![*zeta_eval], vec![*zeta_omega_eval]],
            degree_bound: None,
        })
        .collect();
    // TODO: add B and C


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

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let combined_inner_product =
        combined_inner_product(&[zeta, zeta_omega], &v, &u, es.as_slice(), DOMAIN_SIZE);

    let batch = BatchEvaluationProof {
        sponge: fq_sponge_before_evaluations,
        evaluations,
        evaluation_points: vec![zeta, zeta_omega],
        polyscale: v,
        evalscale: u,
        opening: opening_proof,
        combined_inner_product,
    };

    let group_map = G::Map::setup();
    OpeningProof::verify(srs, &group_map, &mut [batch], &mut thread_rng())
}

