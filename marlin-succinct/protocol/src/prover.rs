/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, PairingEngine};
use oracle::rndoracle::{ProofError};
use ff_fft::{DensePolynomial, Evaluations};
use commitment::commitment::Utils;
use circuits::index::Index;
use crate::marlin_sponge::{FqSponge, FrSponge};

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
        let z = Evaluations::<E::Fr>::from_vec_and_domain(witness.clone(), index.h_group).interpolate();

        // extract/save public part of the padded witness
        let mut witness = witness.clone();
        witness.extend(vec![E::Fr::zero(); index.h_group.size() - witness.len()]);
        let ratio = index.h_group.size() / index.x_group.size();
        let public: Vec<E::Fr> = (0..index.public_inputs).map(|i| {witness[i * ratio]}).collect();

        // evaluate public input polynomial over h_group
        let public_evals = index.h_group.fft
        (
            &Evaluations::<E::Fr>::from_vec_and_domain(public.clone(),
            index.x_group
        ).interpolate());

        // prover computes w polynomial from the witness by subtracting the public polynomial evaluations
        let (w, r) = Evaluations::<E::Fr>::from_vec_and_domain
        (
            witness.iter().enumerate().map
            (
                |elm| {*elm.1 - &public_evals[elm.0]}
            ).collect(),
            index.h_group
        ).interpolate().divide_by_vanishing_poly(index.x_group).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if !r.is_zero() {return Err(ProofError::PolyDivision)}

        // prover computes za, zb polynomials
        let mut zv = vec![vec![E::Fr::zero(); index.h_group.size()]; 2];

        for i in 0..2
        {
            for constraint in index.compiled[i].constraints.iter()
            {
                zv[i][(constraint.1).0] += &(*constraint.0 * &witness[(constraint.1).1]);
            }
        }

        let x_hat = 
            Evaluations::<E::Fr>::from_vec_and_domain(public.clone(), index.x_group).interpolate();
        let x_hat_comm = index.urs.commit(&x_hat)?;

        // prover interpolates the vectors and computes the evaluation polynomial
        let za = Evaluations::<E::Fr>::from_vec_and_domain(zv[0].to_vec(), index.h_group).interpolate();
        let zb = Evaluations::<E::Fr>::from_vec_and_domain(zv[1].to_vec(), index.h_group).interpolate();

        // substitute ZC with ZA*ZB
        let zv = [za.clone(), zb.clone(), &za * &zb];

        // commit to W, ZA, ZB polynomials
        let w_comm = index.urs.commit(&w.clone())?;
        let za_comm = index.urs.commit(&za.clone())?;
        let zb_comm = index.urs.commit(&zb.clone())?;

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb previous proof context into the argument
        fq_sponge.absorb_fr(&E::Fr::one());
        // absorb the public input into the argument
        fq_sponge.absorb_g(& x_hat_comm);
        // absorb W, ZA, ZB polycommitments
        fq_sponge.absorb_g(& w_comm);
        fq_sponge.absorb_g(& za_comm);
        fq_sponge.absorb_g(& zb_comm);

        // sample alpha, eta oracles
        oracles.alpha = fq_sponge.challenge();
        oracles.eta_a = fq_sponge.challenge();
        oracles.eta_b = fq_sponge.challenge();
        oracles.eta_c = fq_sponge.challenge();

        let mut apow = E::Fr::one();
        let mut r: Vec<E::Fr> = (0..index.h_group.size()).map
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
        let h1_comm = index.urs.commit(&h1)?;
        let g1_comm = index.urs.commit_with_degree_bound(&g1, index.h_group.size()-1)?;

        // absorb H1, G1 polycommitments
        fq_sponge.absorb_g(&g1_comm.0);
        fq_sponge.absorb_g(&g1_comm.1);
        fq_sponge.absorb_g(&h1_comm);
        // sample beta[0] oracle
        oracles.beta[0] = fq_sponge.challenge();

        // compute second sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h2, mut g2) = Self::sumcheck_2_compute (index, &ra, &oracles)?;
        let sigma2 = g2.coeffs[0];
        g2.coeffs.remove(0);
        let h2_comm = index.urs.commit(&h2)?;
        let g2_comm = index.urs.commit_with_degree_bound(&g2, index.h_group.size()-1)?;

        // absorb sigma2, g2, h2
        fq_sponge.absorb_fr(&sigma2);
        fq_sponge.absorb_g(&g2_comm.0);
        fq_sponge.absorb_g(&g2_comm.1);
        fq_sponge.absorb_g(&h2_comm);
        // sample beta[1] oracle
        oracles.beta[1] = fq_sponge.challenge();

        // compute third sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h3, mut g3) = Self::sumcheck_3_compute (index, &oracles)?;
        let sigma3 = g3.coeffs[0];
        g3.coeffs.remove(0);
        let h3_comm = index.urs.commit(&h3)?;
        let g3_comm = index.urs.commit_with_degree_bound(&g3, index.k_group.size()-1)?;

        // absorb sigma3, g3, h3
        fq_sponge.absorb_fr(&sigma3);
        fq_sponge.absorb_g(&g3_comm.0);
        fq_sponge.absorb_g(&g3_comm.1);
        fq_sponge.absorb_g(&h3_comm);
        // sample beta[2] & batch oracles
        oracles.beta[2] = fq_sponge.challenge();

        let mut fr_sponge = {
            let digest_before_evaluations = fq_sponge.digest();
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let evals = ProofEvaluations {
            w  : w.evaluate(oracles.beta[0]),
            za : za.evaluate(oracles.beta[0]),
            zb : zb.evaluate(oracles.beta[0]),
            h1 : h1.evaluate(oracles.beta[0]),
            g1 : g1.evaluate(oracles.beta[0]),
            h2 : h2.evaluate(oracles.beta[1]),
            g2 : g2.evaluate(oracles.beta[1]),
            h3 : h3.evaluate(oracles.beta[2]),
            g3 : g3.evaluate(oracles.beta[2]),
            row:
            [
                index.compiled[0].row.evaluate(oracles.beta[2]),
                index.compiled[1].row.evaluate(oracles.beta[2]),
                index.compiled[2].row.evaluate(oracles.beta[2]),
            ],
            col:
            [
                index.compiled[0].col.evaluate(oracles.beta[2]),
                index.compiled[1].col.evaluate(oracles.beta[2]),
                index.compiled[2].col.evaluate(oracles.beta[2]),
            ],
            val:
            [
                index.compiled[0].val.evaluate(oracles.beta[2]),
                index.compiled[1].val.evaluate(oracles.beta[2]),
                index.compiled[2].val.evaluate(oracles.beta[2]),
            ],
        };

        fr_sponge.absorb_evaluations(&x_hat.evaluate(oracles.beta[0]),&evals);

        oracles.batch = fr_sponge.challenge();

        // construct the proof
        // --------------------------------------------------------------------

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
            proof1: index.urs.open_batch
            (
                &vec!
                [
                    za.clone(),
                    zb.clone(),
                    w.clone(),
                    h1.clone(),
                ],
                &vec!
                [
                    (g1.clone(), index.h_group.size() - 1)
                ],
                oracles.batch,
                oracles.beta[0]
            )?,
            proof2: index.urs.open_batch
            (
                &vec!
                [
                    h2.clone()
                ],
                &vec!
                [
                    (g2.clone(), index.h_group.size() - 1)
                ],
                oracles.batch,
                oracles.beta[1]
            )?,
            proof3: index.urs.open_batch
            (
                &vec!
                [
                    h3.clone(),
                    index.compiled[0].row.clone(),
                    index.compiled[1].row.clone(),
                    index.compiled[2].row.clone(),
                    index.compiled[0].col.clone(),
                    index.compiled[1].col.clone(),
                    index.compiled[2].col.clone(),
                    index.compiled[0].val.clone(),
                    index.compiled[1].val.clone(),
                    index.compiled[2].val.clone(),
                ],
                &vec!
                [
                    (g3.clone(), index.k_group.size() - 1)
                ],
                oracles.batch,
                oracles.beta[2]
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
        let mut lagrng: Vec<E::Fr> = index.h_group.elements().map(|elm| {oracles.alpha - &elm}).collect();
        algebra::fields::batch_inversion::<E::Fr>(&mut lagrng);
        let vanish = index.h_group.evaluate_vanishing_polynomial(oracles.alpha);

        // compute and return H1 & G1 polynomials
        (0..3).map
        (
            |i|
            {
                let mut ram = Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.h_group.size()], index.h_group);
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
        ).divide_by_vanishing_poly(index.h_group).map_or(Err(ProofError::PolyDivision), |s| Ok(s))
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
        let lagrng = index.h_group.evaluate_all_lagrange_coefficients(oracles.beta[0]);

        // compute and return H2 & G2 polynomials
        // use the precomputed normalized Lagrange evaluations for interpolation evaluations
        (0..3).map
        (
            |i|
            {
                let mut ramxbval = Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.h_group.size()], index.h_group);
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
        ).divide_by_vanishing_poly(index.h_group).map_or(Err(ProofError::PolyDivision), |s| Ok(s))
    }

    // This function computes polynomials for the third sumchek protocol
    //     RETURN: prover's H3 & G3 polynomials
    pub fn sumcheck_3_compute
    (
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        let vanish = index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &index.h_group.evaluate_vanishing_polynomial(oracles.beta[1]);

        // compute polynomial f3
        let f3 = (0..3).map
        (
            |i|
            {
                Evaluations::<E::Fr>::from_vec_and_domain
                (
                    {
                        let mut fractions: Vec<E::Fr> = (0..index.k_group.size()).map
                        (
                            |j|
                            {
                                (oracles.beta[0] - &index.compiled[i].col_eval_k[j]) *
                                &(oracles.beta[1] - &index.compiled[i].row_eval_k[j])
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
                    index.k_group
                )
            }
        ).fold
        (
            Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.k_group.size()], index.k_group),
            |x, y| &x + &y
        ).interpolate();

        // precompute polynomials (row(X)-oracle1)*(col(X)-oracle2) in evaluation form over b_group
        let crb: Vec<Vec<E::Fr>> =
            (0..3).map(|i| index.compiled[i].compute_row_2_col_1(oracles.beta[0], oracles.beta[1])).collect();

        // compute polynomial a
        let a = (0..3).map
        (
            |i|
            {
                Evaluations::<E::Fr>::from_vec_and_domain
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
                    index.b_group
                )
            }
        ).fold
        (
            Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.b_group.size()], index.b_group),
            |x, y| &x + &y
        ).interpolate();

        // compute polynomial b
        let b = Evaluations::<E::Fr>::from_vec_and_domain
        (
            (0..index.b_group.size()).map
            (
                |i| crb[0][i] * &crb[1][i] * &crb[2][i]
            ).collect(),
            index.b_group
        ).interpolate();

        // compute quotient and remainder
        match (&a - &(&b * &f3)).divide_by_vanishing_poly(index.k_group)
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
    pub batch: F,
    pub beta: [F; 3],
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        Self
        {
            alpha: F::zero(),
            eta_a: F::zero(),
            eta_b: F::zero(),
            eta_c: F::zero(),
            batch: F::zero(),
            beta: [F::zero(), F::zero(), F::zero()],
        }
    }
}
