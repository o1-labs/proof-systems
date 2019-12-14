/********************************************************************************************

This source file implements prover's zk-proof primitives.

*********************************************************************************************/

use algebra::{Field, PairingEngine};
use oracle::rndoracle::{RandomOracleArgument, ProofError};
use ff_fft::{DensePolynomial, Evaluations};
use circuits::index::{Witness, Index};

#[derive(Clone)]
pub struct ProverProof<E: PairingEngine>
{
    // polynomial commitments
    pub w_comm: E::G1Affine,
    pub za_comm: E::G1Affine,
    pub zb_comm: E::G1Affine,
    pub h1_comm: E::G1Affine,
    pub g1_comm: E::G1Affine,
    pub h2_comm: E::G1Affine,
    pub g2_comm: E::G1Affine,
    pub h3_comm: E::G1Affine,
    pub g3_comm: E::G1Affine,

    // batched commitment opening proofs
    pub proof1: E::G1Affine,
    pub proof2: E::G1Affine,
    pub proof3: E::G1Affine,

    // polynomial evaluations
    pub w_eval: E::Fr,
    pub za_eval: E::Fr,
    pub zb_eval: E::Fr,
    pub h1_eval: E::Fr,
    pub g1_eval: E::Fr,
    pub h2_eval: E::Fr,
    pub g2_eval: E::Fr,
    pub h3_eval: E::Fr,
    pub g3_eval: E::Fr,
    pub row_eval: [E::Fr; 3],
    pub col_eval: [E::Fr; 3],
    pub val_eval: [E::Fr; 3],

    // prover's scalars
    pub sigma2: E::Fr,
    pub sigma3: E::Fr,

    // public part of the witness
    pub public: Witness<E::Fr>
}

impl<E: PairingEngine> ProverProof<E>
{
    // This function constructs prover's zk-proof from the witness & the Index against URS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
    (
        witness: &Witness::<E::Fr>,
        index: &Index<E>
    ) -> Result<Self, ProofError>
    {
        if index.compiled[0].constraints.shape().1 != witness.0.len() || witness.1 == 0
        {
            return Err(ProofError::WitnessCsInconsistent)
        }

        // random oracles have to be retrieved from the non-interactive argument
        // context sequentually with adding argument-specific payload to the context

        let mut oracles = RandomOracles::<E::Fr>::zero();

        // prover computes z, w polynomials, second is the restriction of the first on the secret part of the witness
        let z = Evaluations::<E::Fr>::from_vec_and_domain(witness.0.clone(), index.h_group).interpolate();

        // extract secret of the witness
        let mut w = witness.clone();
        for i in 0..w.1 {w.0[i] = E::Fr::zero()}
        let w = Evaluations::<E::Fr>::from_vec_and_domain(w.0, index.h_group).interpolate();

        // prover computes za, zb polynomials
        let mut zv = vec![vec![E::Fr::zero(); index.h_group.size()]; 2];

        for i in 0..2
        {
            for constraint in index.compiled[i].constraints.iter()
            {
                zv[i][(constraint.1).0] += &(*constraint.0 * &witness.0[(constraint.1).1]);
            }
        }

        // save public part of the witness
        let mut public = witness.clone();
        for i in public.1..public.0.len() {public.0[i] = E::Fr::zero()}

        // prover interpolates the vectors and computes the evaluation polynomial
        let za = Evaluations::<E::Fr>::from_vec_and_domain(zv[0].to_vec(), index.h_group).interpolate();
        let zb = Evaluations::<E::Fr>::from_vec_and_domain(zv[1].to_vec(), index.h_group).interpolate();

        // substitute ZC with ZA*ZB
        let zv = [za.clone(), zb.clone(), &za * &zb]; 

        // commit to W, ZA, ZB polynomials
        let w_comm = index.urs.commit(&w.clone(), index.h_group.size())?;
        let za_comm = index.urs.commit(&za.clone(), index.h_group.size())?;
        let zb_comm = index.urs.commit(&zb.clone(), index.h_group.size())?;

        // the transcript of the random oracle non-interactive argument
        let mut argument = RandomOracleArgument::<E>::new(index.oracle_params.clone());
        
        // absorb previous proof context into the argument
        argument.commit_scalars(&[E::Fr::one()]);
        // absorb the public input into the argument
        argument.commit_scalars(&witness.0[0..witness.1]);
        // absorb W, ZA, ZB polycommitments
        argument.commit_points(&[w_comm, za_comm, zb_comm])?;

        // sample alpha, eta oracles
        oracles.alpha = argument.challenge();
        oracles.eta_a = argument.challenge();
        oracles.eta_b = argument.challenge();
        oracles.eta_c = argument.challenge();

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
        let h1_comm = index.urs.commit(&h1, index.h_group.size()*2)?;
        let g1_comm = index.urs.commit(&g1, index.h_group.size()-1)?;

        // absorb H1, G1 polycommitments
        argument.commit_points(&[h1_comm, g1_comm])?;
        // sample beta[0] oracle
        oracles.beta[0] = argument.challenge();

        // compute second sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h2, mut g2) = Self::sumcheck_2_compute (index, &ra, &oracles)?;
        let sigma2 = g2.coeffs[0];
        g2.coeffs.remove(0);

        // absorb sigma2 scalar
        argument.commit_scalars(&[sigma2]);
        // sample beta[1] oracle
        oracles.beta[1] = argument.challenge();

        // compute third sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h3, mut g3) = Self::sumcheck_3_compute (index, &oracles)?;
        let sigma3 = g3.coeffs[0];
        g3.coeffs.remove(0);

        // absorb sigma3 scalar
        argument.commit_scalars(&[sigma3]);
        // sample beta[2] & batch oracles
        oracles.beta[2] = argument.challenge();
        oracles.batch = argument.challenge();

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
            h2_comm: index.urs.commit(&h2, index.h_group.size())?,
            g2_comm: index.urs.commit(&g2, index.h_group.size()-1)?,
            h3_comm: index.urs.commit(&h3, index.h_group.size()*6)?,
            g3_comm: index.urs.commit(&g3, index.h_group.size()-1)?,

            // polynomial commitment batched opening proofs
            proof1: index.urs.open_batch
            (
                &vec!
                [
                    za.clone(),
                    zb.clone(),
                    w.clone(),
                    h1.clone(),
                    g1.clone(),
                ],
                oracles.batch,
                oracles.beta[0]
            )?,
            proof2: index.urs.open_batch
            (
                &vec!
                [
                    h2.clone(),
                    g2.clone()
                ],
                oracles.batch,
                oracles.beta[1]
            )?,
            proof3: index.urs.open_batch
            (
                &vec!
                [
                    h3.clone(),
                    g3.clone(),
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
                oracles.batch,
                oracles.beta[2]
            )?,

            // polynomial evaluations
            w_eval  : w.clone().evaluate(oracles.beta[0]),
            za_eval : za.evaluate(oracles.beta[0]),
            zb_eval : zb.evaluate(oracles.beta[0]),
            h1_eval : h1.evaluate(oracles.beta[0]),
            g1_eval : g1.evaluate(oracles.beta[0]),
            h2_eval : h2.evaluate(oracles.beta[1]),
            g2_eval : g2.evaluate(oracles.beta[1]),
            h3_eval : h3.evaluate(oracles.beta[2]),
            g3_eval : g3.evaluate(oracles.beta[2]),
            row_eval:
            [
                index.compiled[0].row.evaluate(oracles.beta[2]),
                index.compiled[1].row.evaluate(oracles.beta[2]),
                index.compiled[2].row.evaluate(oracles.beta[2]),
            ],
            col_eval:
            [
                index.compiled[0].col.evaluate(oracles.beta[2]),
                index.compiled[1].col.evaluate(oracles.beta[2]),
                index.compiled[2].col.evaluate(oracles.beta[2]),
            ],
            val_eval:
            [
                index.compiled[0].val.evaluate(oracles.beta[2]),
                index.compiled[1].val.evaluate(oracles.beta[2]),
                index.compiled[2].val.evaluate(oracles.beta[2]),
            ],

            // prover's scalars
            sigma2,
            sigma3,

            // public part of the witness
            public: public,
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
        // precompute Lagrange polynomial evaluations
        let mut lagrng: Vec<E::Fr> = index.h_group.elements().map(|elm| {oracles.alpha - &elm}).collect();
        algebra::fields::batch_inversion::<E::Fr>(&mut lagrng);
        let vanish = index.h_group.evaluate_vanishing_polynomial(oracles.alpha);
        let lagrng: Vec<E::Fr> = lagrng.iter().map(|elm| {vanish * &elm}).collect();

        let mut sumg = DensePolynomial::<E::Fr>::zero();
        
        for i in 0..3
        {
            let mut ram = Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.h_group.size()], index.h_group);
            for val in index.compiled[i].constraints.iter()
            {
                ram.evals[(val.1).1] += &(*val.0 * &lagrng[(val.1).0]);
            }

            // scale with eta's and add up
            sumg += &(&(&(ra * &zm[i]) - &(&ram.interpolate() * &z)) *
                &DensePolynomial::<E::Fr>::from_coefficients_slice(&[[oracles.eta_a, oracles.eta_b, oracles.eta_c][i]]));
        }
        // compute quotient and remainder
        sumg.divide_by_vanishing_poly(index.h_group).map_or(Err(ProofError::PolyDivision), |r| Ok(r))
    }

    // This function computes polynomials for the second sumchek protocol
    //     RETURN: prover's H1 & G1 polynomials
    pub fn sumcheck_2_compute
    (
        index: &Index<E>,
        ra: &DensePolynomial<E::Fr>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        // precompute Lagrange polynomial evaluations
        let h_elems: Vec<E::Fr> = index.h_group.elements().map(|elm| {elm}).collect();
        let mut lagrng: Vec<E::Fr> = h_elems.iter().map
        (
            |elm|
            {
                (oracles.beta[0] - &elm) * &index.h_group.size_as_field_element
            }
        ).collect();
        algebra::fields::batch_inversion::<E::Fr>(&mut lagrng);
        let vanish = index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]);
        let lagrng: Vec<E::Fr> = lagrng.iter().map(|elm| {vanish * &elm}).collect();

        let mut ramxbg = DensePolynomial::<E::Fr>::zero();
        for i in 0..3
        {
            let mut ramxbval = Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.h_group.size()], index.h_group);
            for val in index.compiled[i].constraints.iter()
            {
                // we use normalized Lagrange evaluation for interpolation evaluation
                ramxbval.evals[(val.1).0] += &(*val.0 * &lagrng[(val.1).1] * &h_elems[(val.1).1]);
            }

            // scale with eta's and add up
            ramxbg +=
                &(&(ra * &ramxbval.interpolate()) *
                &DensePolynomial::<E::Fr>::from_coefficients_slice(&[[oracles.eta_a, oracles.eta_b, oracles.eta_c][i]]));
        }
        // compute quotient and remainder
        ramxbg.divide_by_vanishing_poly(index.h_group).map_or(Err(ProofError::PolyDivision), |r| Ok(r))
    }

    // This function computes polynomials for the third sumchek protocol
    //     RETURN: prover's H1 & G1 polynomials
    pub fn sumcheck_3_compute
    (
        index: &Index<E>,
        oracles: &RandomOracles<E::Fr>
    ) -> Result<(DensePolynomial<E::Fr>, DensePolynomial<E::Fr>), ProofError>
    {
        // compute polynomials h3 & g3 for the third sumcheck argument
        let vanish = index.h_group.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &index.h_group.evaluate_vanishing_polynomial(oracles.beta[1]);

        // compute polynomial f3
        let mut f3 = Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::zero(); index.h_group.size()], index.h_group);
        for i in 0..3
        {
            // scale with eta's and add up
            f3 += &Evaluations::<E::Fr>::from_vec_and_domain
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
                    fractions.iter().enumerate().map(|(j, elm)| {vanish * &index.compiled[i].val_eval_k[j] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i] * &elm}).collect()
                },
                index.h_group
            );
        }
        let f3 = f3.interpolate();

        // precompute polnomials (row(X)-oracle1)*(col(X)-oracle2)
        let crb: Vec<DensePolynomial<E::Fr>> =
            (0..3).map(|i| index.compiled[i].compute_fraction(oracles.beta[0], oracles.beta[1])).collect();

        // compute polynomial a
        let mut a = DensePolynomial::<E::Fr>::zero();
        for i in 0..3
        {
            let mut x = &index.compiled[i].val *
                &DensePolynomial::<E::Fr>::from_coefficients_slice(&[[oracles.eta_a, oracles.eta_b, oracles.eta_c][i]]);
            for j in 0..3 {if i != j {x = &x * &crb[j]}}
            a += &x;
        }
        a = &a * &DensePolynomial::<E::Fr>::from_coefficients_slice(&[vanish]);

        // compute polynomial h3
        let mut b = f3.clone();
        for i in 0..3 {b = &b * &crb[i]}
        a -= &b;

        // compute quotient and remainder
        match a.divide_by_vanishing_poly(index.k_group)
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
