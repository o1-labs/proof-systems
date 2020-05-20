/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, FftField, PairingEngine, Zero, One};
use oracle::rndoracle::{ProofError};
use ff_fft::{DensePolynomial, Radix2EvaluationDomain as Domain, Evaluations, EvaluationDomain, GeneralEvaluationDomain};
use commitment_pairing::commitment::Utils;
use circuits_pairing::index::Index;
use oracle::marlin_sponge::{FqSponge, ScalarChallenge};
use crate::marlin_sponge::{FrSponge};

#[derive(Clone)]
pub struct ProofEvaluations<Fr> {
    pub w: Fr,
    pub za: Fr,
    pub zb: Fr,
    pub h1: Fr,
    pub g1: Fr,
    pub h2: Fr,
    pub g2: Fr,
    pub h3: Fr,
    pub g3: Fr,
    pub row: [Fr; 3],
    pub col: [Fr; 3],
    pub val: [Fr; 3],
    pub rc: [Fr; 3],
}

#[derive(Clone)]
pub struct ProverProof<E: PairingEngine>
{
    // polynomial commitments
    pub w_comm: E::G1Affine,
    pub za_comm: E::G1Affine,
    pub zb_comm: E::G1Affine,
    pub h1_comm: E::G1Affine,
    pub g1_comm: (E::G1Affine, E::G1Affine),
    pub h2_comm: E::G1Affine,
    pub g2_comm: (E::G1Affine, E::G1Affine),
    pub h3_comm: E::G1Affine,
    pub g3_comm: (E::G1Affine, E::G1Affine),

    // batched commitment opening proofs
    pub proof1: E::G1Affine,
    pub proof2: E::G1Affine,
    pub proof3: E::G1Affine,

    // polynomial evaluations
    pub evals : ProofEvaluations<E::Fr>,

    // prover's scalars
    pub sigma2: E::Fr,
    pub sigma3: E::Fr,

    // public part of the witness
    pub public: Vec<E::Fr>
}

fn evals_from_coeffs<F: FftField>(
    v : Vec<F>,
    d : Domain<F>) -> Evaluations<F, GeneralEvaluationDomain<F>> {
    Evaluations::<F>::from_vec_and_domain(v, GeneralEvaluationDomain::Radix2(d))
}

impl<E: PairingEngine> ProverProof<E>
{
    // This function constructs prover's zk-proof from the witness & the Index against URS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        witness: &Vec::<E::Fr>,
        index: &Index<E>
    ) -> Result<Self, ProofError>
    {
        // random oracles have to be retrieved from the non-interactive argument
        // context sequentually with adding argument-specific payload to the context

        let mut oracles = RandomOracles::<E::Fr>::zero();

        // prover computes z polynomial
        let z = evals_from_coeffs(witness.clone(), index.domains.h).interpolate();

        // extract/save public part of the padded witness
        let mut witness = witness.clone();
        witness.extend(vec![E::Fr::zero(); index.domains.h.size() - witness.len()]);
        let ratio = index.domains.h.size() / index.domains.x.size();
        let public: Vec<E::Fr> = (0..index.public_inputs).map(|i| {witness[i * ratio]}).collect();

        // evaluate public input polynomial over domains.h
        let public_evals = index.domains.h.fft
        (
            &evals_from_coeffs(public.clone(),
            index.domains.x
        ).interpolate());

        // prover computes w polynomial from the witness by subtracting the public polynomial evaluations
        let (w, r) = evals_from_coeffs
        (
            witness.iter().enumerate().map
            (
                |elm| {*elm.1 - &public_evals[elm.0]}
            ).collect(),
            index.domains.h
        ).interpolate().divide_by_vanishing_poly(index.domains.x).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if !r.is_zero() {return Err(ProofError::PolyDivision)}

        // prover computes za, zb polynomials
        let mut zv = vec![vec![E::Fr::zero(); index.domains.h.size()]; 2];

        for i in 0..2
        {
            for constraint in index.compiled[i].constraints.iter()
            {
                zv[i][(constraint.1).0] += &(*constraint.0 * &witness[(constraint.1).1]);
            }
        }

        let urs = index.urs.get_ref();

        let x_hat = 
            evals_from_coeffs(public.clone(), index.domains.x).interpolate();
        let x_hat_comm = urs.commit(&x_hat)?;

        // prover interpolates the vectors and computes the evaluation polynomial
        let za = evals_from_coeffs(zv[0].to_vec(), index.domains.h).interpolate();
        let zb = evals_from_coeffs(zv[1].to_vec(), index.domains.h).interpolate();

        // substitute ZC with ZA*ZB
        let zv = [za.clone(), zb.clone(), &za * &zb];

        // commit to W, ZA, ZB polynomials
        let w_comm = urs.commit(&w.clone())?;
        let za_comm = urs.commit(&za.clone())?;
        let zb_comm = urs.commit(&zb.clone())?;

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input iand W, ZA, ZB polycommitments nto the argument
        fq_sponge.absorb_g(& [x_hat_comm, w_comm, za_comm, zb_comm]);

        // sample alpha, eta oracles
        oracles.alpha = fq_sponge.challenge();
        oracles.eta_a = fq_sponge.challenge();
        oracles.eta_b = fq_sponge.challenge();
        oracles.eta_c = fq_sponge.challenge();

        let mut apow = E::Fr::one();
        let mut r: Vec<E::Fr> = (0..index.domains.h.size()).map
        (
            |i|
            {
                if i > 0 {apow *= &oracles.alpha}
                apow
            }
        ).collect();
        r.reverse();
        let ra = DensePolynomial::<E::Fr>::from_coefficients_vec(r);

        // compute first sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h1, mut g1) = Self::sumcheck_1_compute (index, &ra, &zv, &z, &oracles)?;
        if !g1.coeffs[0].is_zero() {return Err(ProofError::SumCheck)}
        g1.coeffs.remove(0);

        // commit to H1 & G1 polynomials and
        let h1_comm = urs.commit(&h1)?;
        let g1_comm = urs.commit_with_degree_bound(&g1, index.domains.h.size()-1)?;

        // absorb H1, G1 polycommitments
        fq_sponge.absorb_g(&[g1_comm.0, g1_comm.1, h1_comm]);
        // sample beta[0] oracle
        oracles.beta[0] = ScalarChallenge(fq_sponge.challenge());

        // compute second sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h2, mut g2) = Self::sumcheck_2_compute (index, &ra, &oracles)?;
        let sigma2 = g2.coeffs[0];
        g2.coeffs.remove(0);
        let h2_comm = urs.commit(&h2)?;
        let g2_comm = urs.commit_with_degree_bound(&g2, index.domains.h.size()-1)?;

        // absorb sigma2, g2, h2
        fq_sponge.absorb_fr(&sigma2);
        fq_sponge.absorb_g(&[g2_comm.0, g2_comm.1, h2_comm]);
        // sample beta[1] oracle
        oracles.beta[1] = ScalarChallenge(fq_sponge.challenge());

        // compute third sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h3, mut g3) = Self::sumcheck_3_compute (index, &oracles)?;
        let sigma3 = g3.coeffs[0];
        g3.coeffs.remove(0);
        let h3_comm = urs.commit(&h3)?;
        let g3_comm = urs.commit_with_degree_bound(&g3, index.domains.k.size()-1)?;

        // absorb sigma3, g3, h3
        fq_sponge.absorb_fr(&sigma3);
        fq_sponge.absorb_g(&[g3_comm.0, g3_comm.1, h3_comm]);
        // sample beta[2] & batch oracles
        oracles.beta[2] = ScalarChallenge(fq_sponge.challenge());
        oracles.r_k = ScalarChallenge(fq_sponge.challenge());

        let digest_before_evaluations = fq_sponge.digest();
        oracles.digest_before_evaluations = digest_before_evaluations;

        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let endo = &index.endo_r;
        let beta : Vec<_> = oracles.beta.iter().map(|x| x.to_field(endo)).collect();

        let evals = ProofEvaluations {
            w  : w.evaluate(beta[0]),
            za : za.evaluate(beta[0]),
            zb : zb.evaluate(beta[0]),
            h1 : h1.evaluate(beta[0]),
            g1 : g1.evaluate(beta[0]),
            h2 : h2.evaluate(beta[1]),
            g2 : g2.evaluate(beta[1]),
            h3 : h3.evaluate(beta[2]),
            g3 : g3.evaluate(beta[2]),
            row:
            [
                index.compiled[0].row.evaluate(beta[2]),
                index.compiled[1].row.evaluate(beta[2]),
                index.compiled[2].row.evaluate(beta[2]),
            ],
            col:
            [
                index.compiled[0].col.evaluate(beta[2]),
                index.compiled[1].col.evaluate(beta[2]),
                index.compiled[2].col.evaluate(beta[2]),
            ],
            val:
            [
                index.compiled[0].val.evaluate(beta[2]),
                index.compiled[1].val.evaluate(beta[2]),
                index.compiled[2].val.evaluate(beta[2]),
            ],
            rc:
            [
                index.compiled[0].rc.evaluate(beta[2]),
                index.compiled[1].rc.evaluate(beta[2]),
                index.compiled[2].rc.evaluate(beta[2]),
            ],
        };

        let x_hat_beta1 = x_hat.evaluate(beta[0]);
        oracles.x_hat_beta1 = x_hat_beta1;

        fr_sponge.absorb_evaluations(&x_hat_beta1, &evals);

        oracles.batch = fr_sponge.challenge();
        oracles.r = fr_sponge.challenge();

        // construct the proof
        // --------------------------------------------------------------------

        let batch_chal = oracles.batch.to_field(endo);

        Ok(ProverProof
        {
            // polynomial commitments
            w_comm,
            za_comm,
            zb_comm,
            h1_comm,
            g1_comm,
            h2_comm,
            g2_comm,
            h3_comm,
            g3_comm,

            // polynomial commitment batched opening proofs
            proof1: urs.open
            (
                vec!
                [
                    &x_hat,
                    &w,
                    &za,
                    &zb,
                    &g1,
                    &h1,
                ],
                batch_chal,
                beta[0]
            )?,
            proof2: urs.open
            (
                vec!
                [
                    &g2,
                    &h2,
                ],
                batch_chal,
                beta[1]
            )?,
            proof3: urs.open
            (
                vec!
                [
                    &g3,
                    &h3,
                    &index.compiled[0].row,
                    &index.compiled[1].row,
                    &index.compiled[2].row,
                    &index.compiled[0].col,
                    &index.compiled[1].col,
                    &index.compiled[2].col,
                    &index.compiled[0].val,
                    &index.compiled[1].val,
                    &index.compiled[2].val,
                    &index.compiled[0].rc,
                    &index.compiled[1].rc,
                    &index.compiled[2].rc,
                ],
                batch_chal,
                beta[2]
            )?,

            // polynomial evaluations
            evals,

            // prover's scalars
            sigma2,
            sigma3,

            // public part of the witness
            public
        })
    }

    // This function computes polynomials for the first sumchek protocol
    //     RETURN: prover's H1 & G1 polynomials
    pub fn sumcheck_1_compute
    (
        index: &Index<E>,
        ra: &DensePolynomial<E::Fr>,
        zm: &[DensePolynomial<E::Fr>; 3],
        z: &DensePolynomial<E::Fr>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        // precompute Lagrange polynomial denominators
        let mut lagrng: Vec<E::Fr> = index.domains.h.elements().map(|elm| {oracles.alpha - &elm}).collect();
        algebra::fields::batch_inversion::<E::Fr>(&mut lagrng);
        let vanish = index.domains.h.evaluate_vanishing_polynomial(oracles.alpha);

        // compute and return H1 & G1 polynomials
        (0..3).map
        (
            |i|
            {
                let mut ram = evals_from_coeffs(vec![E::Fr::zero(); index.domains.h.size()], index.domains.h);
                for val in index.compiled[i].constraints.iter()
                {
                    ram.evals[(val.1).1] += &(vanish * val.0 * &lagrng[(val.1).0]);
                }
                (i, ram)
            }
        ).fold
        (
            DensePolynomial::<E::Fr>::zero(),
            |x, (i, y)|
            // scale with eta's and add up
            &x + &(&(ra * &zm[i]) - &(&y.interpolate() * &z)).scale([oracles.eta_a, oracles.eta_b, oracles.eta_c][i])
        // compute quotient and remainder
        ).divide_by_vanishing_poly(index.domains.h).map_or(Err(ProofError::PolyDivision), |s| Ok(s))
    }

    // This function computes polynomials for the second sumchek protocol
    //     RETURN: prover's H2 & G2 polynomials
    pub fn sumcheck_2_compute
    (
        index: &Index<E>,
        ra: &DensePolynomial<E::Fr>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        // precompute Lagrange polynomial evaluations
        let lagrng = index.domains.h.evaluate_all_lagrange_coefficients(oracles.beta[0].to_field(&index.endo_r));

        // compute and return H2 & G2 polynomials
        // use the precomputed normalized Lagrange evaluations for interpolation evaluations
        (0..3).map
        (
            |i|
            {
                let mut ramxbval = evals_from_coeffs(vec![E::Fr::zero(); index.domains.h.size()], index.domains.h);
                for val in index.compiled[i].constraints.iter()
                {
                    ramxbval.evals[(val.1).0] += &(*val.0 * &lagrng[(val.1).1]);
                }
                (i, ramxbval)
            }
        ).fold
        (
            DensePolynomial::<E::Fr>::zero(),
            |x, (i, y)|
            // scale with eta's and add up
            &x + &(&(ra * &y.interpolate()).scale([oracles.eta_a, oracles.eta_b, oracles.eta_c][i]))
        // compute quotient and remainder
        ).divide_by_vanishing_poly(index.domains.h).map_or(Err(ProofError::PolyDivision), |s| Ok(s))
    }

    // This function computes polynomials for the third sumchek protocol
    //     RETURN: prover's H3 & G3 polynomials
    pub fn sumcheck_3_compute
    (
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        let beta0 = oracles.beta[0].to_field(&index.endo_r);
        let beta1 = oracles.beta[1].to_field(&index.endo_r);

        let vanish = index.domains.h.evaluate_vanishing_polynomial(beta0) *
            &index.domains.h.evaluate_vanishing_polynomial(beta1);

        // compute polynomial f3
        let f3 = (0..3).map
        (
            |i|
            {
                evals_from_coeffs
                (
                    {
                        let mut fractions: Vec<E::Fr> = (0..index.domains.k.size()).map
                        (
                            |j|
                            {
                                (beta0 - &index.compiled[i].col_eval_k[j]) *
                                &(beta1 - &index.compiled[i].row_eval_k[j])
                            }
                        ).collect();
                        algebra::fields::batch_inversion::<E::Fr>(&mut fractions);
                        fractions.iter().enumerate().map
                        (
                            |(j, elm)|
                            {
                                vanish * &index.compiled[i].val_eval_k[j] *
                                // scale with eta's
                                &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i] * &elm
                            }
                        ).collect()
                    },
                    index.domains.k
                )
            }
        ).fold
        (
            evals_from_coeffs(vec![E::Fr::zero(); index.domains.k.size()], index.domains.k),
            |x, y| &x + &y
        ).interpolate();

        // precompute polynomials (row(X)-oracle1)*(col(X)-oracle2) in evaluation form over domains.b
        let crb: Vec<Vec<E::Fr>> =
            (0..3).map(|i| index.compiled[i].compute_row_2_col_1(beta0, beta1)).collect();

        // compute polynomial a
        let a = (0..3).map
        (
            |i|
            {
                evals_from_coeffs
                (
                    index.compiled[i].val_eval_b.evals.iter().enumerate().map
                    (
                        |(k, val)|
                        {
                            let mut eval = [oracles.eta_a, oracles.eta_b, oracles.eta_c][i] * val * &vanish;
                            for j in 0..3 {if i != j {eval *= &crb[j][k]}}
                            eval
                        }
                    ).collect(),
                    index.domains.b
                )
            }
        ).fold
        (
            evals_from_coeffs(vec![E::Fr::zero(); index.domains.b.size()], index.domains.b),
            |x, y| &x + &y
        ).interpolate();

        // compute polynomial b
        let b = evals_from_coeffs
        (
            (0..index.domains.b.size()).map
            (
                |i| crb[0][i] * &crb[1][i] * &crb[2][i]
            ).collect(),
            index.domains.b
        ).interpolate();

        // compute quotient and remainder
        match (&a - &(&b * &f3)).divide_by_vanishing_poly(index.domains.k)
        {
            Some((q, r)) => {if r.coeffs.len() > 0 {return Err(ProofError::PolyDivision)} else {return Ok((q, f3))}}
            _ => return Err(ProofError::PolyDivision)
        }
    }
}

pub struct RandomOracles<F: Field>
{
    pub alpha: F,
    pub eta_a: F,
    pub eta_b: F,
    pub eta_c: F,
    pub beta: [ScalarChallenge<F>; 3],
    pub r_k : ScalarChallenge<F>,

    pub x_hat_beta1: F,
    pub digest_before_evaluations: F,

    // Sampled using the other sponge
    pub batch: ScalarChallenge<F>,
    pub r: ScalarChallenge<F>,
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        let c = ScalarChallenge(F::zero());
        Self
        {
            alpha: F::zero(),
            eta_a: F::zero(),
            eta_b: F::zero(),
            eta_c: F::zero(),
            batch: c,
            beta: [c, c, c],
            r: c,
            x_hat_beta1: F::zero(),
            digest_before_evaluations: F::zero(),
            r_k: c,
        }
    }
}
