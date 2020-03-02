/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve};
use oracle::{FqSponge, rndoracle::{ProofError}};
use ff_fft::{DensePolynomial, Evaluations};
use commitment_dlog::commitment::{Utils, OpeningProof, b_poly_coefficients, product};
use circuits_dlog::index::Index;
use crate::marlin_sponge::{FrSponge};
use rand_core::RngCore;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;
 
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
pub struct ProverProof<G: AffineCurve>
{
    // polynomial commitments
    pub w_comm: G,
    pub za_comm: G,
    pub zb_comm: G,
    pub h1_comm: G,
    pub g1_comm: (G, G),
    pub h2_comm: G,
    pub g2_comm: (G, G),
    pub h3_comm: G,
    pub g3_comm: (G, G),

    // batched commitment opening proofs
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    pub evals: [ProofEvaluations<Fr<G>>; 3],

    // prover's scalars
    pub sigma2: Fr<G>,
    pub sigma3: Fr<G>,

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, G)>,
}

impl<G: AffineCurve> ProverProof<G>
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        witness: &Vec::<Fr<G>>,
        index: &Index<G>,
        prev_challenges: Vec< (Vec<Fr<G>>, G) >,
        rng: &mut dyn RngCore,
    ) 
    -> Result<Self, ProofError>
    {
        // random oracles have to be retrieved from the non-interactive argument
        // context sequentually with adding argument-specific payload to the context

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // prover computes z polynomial
        let z = Evaluations::<Fr<G>>::from_vec_and_domain(witness.clone(), index.domains.h).interpolate();

        // extract/save public part of the padded witness
        let mut witness = witness.clone();
        witness.extend(vec![Fr::<G>::zero(); index.domains.h.size() - witness.len()]);
        let ratio = index.domains.h.size() / index.domains.x.size();
        let public: Vec<Fr<G>> = (0..index.public_inputs).map(|i| {witness[i * ratio]}).collect();

        // evaluate public input polynomial over domains.h
        let public_evals = index.domains.h.fft
        (
            &Evaluations::<Fr<G>>::from_vec_and_domain(public.clone(),
            index.domains.x
        ).interpolate());

        // prover computes w polynomial from the witness by subtracting the public polynomial evaluations
        let (w, r) = Evaluations::<Fr<G>>::from_vec_and_domain
        (
            witness.iter().enumerate().map
            (
                |elm| {*elm.1 - &public_evals[elm.0]}
            ).collect(),
            index.domains.h
        ).interpolate().divide_by_vanishing_poly(index.domains.x).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if !r.is_zero() {return Err(ProofError::PolyDivision)}

        // prover computes za, zb polynomials
        let mut zv = vec![vec![Fr::<G>::zero(); index.domains.h.size()]; 2];

        for i in 0..2
        {
            for constraint in index.compiled[i].constraints.iter()
            {
                zv[i][(constraint.1).0] += &(*constraint.0 * &witness[(constraint.1).1]);
            }
        }

        let x_hat = 
            Evaluations::<Fr<G>>::from_vec_and_domain(public.clone(), index.domains.x).interpolate();
         // TODO: Should have no degree bound when we add the correct degree bound method
        let x_hat_comm = index.srs.get_ref().commit_no_degree_bound(&x_hat)?;

        // prover interpolates the vectors and computes the evaluation polynomial
        let za = Evaluations::<Fr<G>>::from_vec_and_domain(zv[0].to_vec(), index.domains.h).interpolate();
        let zb = Evaluations::<Fr<G>>::from_vec_and_domain(zv[1].to_vec(), index.domains.h).interpolate();

        // substitute ZC with ZA*ZB
        let zv = [za.clone(), zb.clone(), &za * &zb];

        // commit to W, ZA, ZB polynomials
        let w_comm = index.srs.get_ref().commit_no_degree_bound(&w.clone())?;
        let za_comm = index.srs.get_ref().commit_no_degree_bound(&za.clone())?;
        let zb_comm = index.srs.get_ref().commit_no_degree_bound(&zb.clone())?;

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());
        
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

        let mut apow = Fr::<G>::one();
        let mut r: Vec<Fr<G>> = (0..index.domains.h.size()).map
        (
            |i|
            {
                if i > 0 {apow *= &oracles.alpha}
                apow
            }
        ).collect();
        r.reverse();
        let ra = DensePolynomial::<Fr<G>>::from_coefficients_vec(r);

        // compute first sumcheck argument polynomials
        // --------------------------------------------------------------------

        let (h1, mut g1) = Self::sumcheck_1_compute (index, &ra, &zv, &z, &oracles)?;
        if !g1.coeffs[0].is_zero() {return Err(ProofError::SumCheck)}
        g1.coeffs.remove(0);

        // commit to H1 & G1 polynomials and
        let h1_comm = index.srs.get_ref().commit_no_degree_bound(&h1)?;
        let g1_comm = index.srs.get_ref().commit_with_degree_bound(&g1, index.domains.h.size()-1)?;

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
        let h2_comm = index.srs.get_ref().commit_no_degree_bound(&h2)?;
        let g2_comm = index.srs.get_ref().commit_with_degree_bound(&g2, index.domains.h.size()-1)?;

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
        let h3_comm = index.srs.get_ref().commit_no_degree_bound(&h3)?;
        let g3_comm = index.srs.get_ref().commit_with_degree_bound(&g3, index.domains.k.size()-1)?;

        // absorb sigma3 scalar
        fq_sponge.absorb_fr(&sigma3);
        fq_sponge.absorb_g(&g3_comm.0);
        fq_sponge.absorb_g(&g3_comm.1);
        fq_sponge.absorb_g(&h3_comm);
        // sample beta[2] & batch oracles
        oracles.beta[2] = fq_sponge.challenge();

        let fq_sponge_before_evaluations = fq_sponge.clone();

        let mut fr_sponge = {
            let digest_before_evaluations = fq_sponge.digest();
            oracles.digest_before_evaluations = digest_before_evaluations;

            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&digest_before_evaluations);
            s
        };

        let evals =
        {
            let evl = (0..3).map
            (
                |i| ProofEvaluations
                {
                    w  : w.evaluate(oracles.beta[i]),
                    za : za.evaluate(oracles.beta[i]),
                    zb : zb.evaluate(oracles.beta[i]),
                    h1 : h1.evaluate(oracles.beta[i]),
                    g1 : g1.evaluate(oracles.beta[i]),
                    h2 : h2.evaluate(oracles.beta[i]),
                    g2 : g2.evaluate(oracles.beta[i]),
                    h3 : h3.evaluate(oracles.beta[i]),
                    g3 : g3.evaluate(oracles.beta[i]),
                    row:
                    [
                        index.compiled[0].row.evaluate(oracles.beta[i]),
                        index.compiled[1].row.evaluate(oracles.beta[i]),
                        index.compiled[2].row.evaluate(oracles.beta[i]),
                    ],
                    col:
                    [
                        index.compiled[0].col.evaluate(oracles.beta[i]),
                        index.compiled[1].col.evaluate(oracles.beta[i]),
                        index.compiled[2].col.evaluate(oracles.beta[i]),
                    ],
                    val:
                    [
                        index.compiled[0].val.evaluate(oracles.beta[i]),
                        index.compiled[1].val.evaluate(oracles.beta[i]),
                        index.compiled[2].val.evaluate(oracles.beta[i]),
                    ],
                    rc:
                    [
                        index.compiled[0].rc.evaluate(oracles.beta[i]),
                        index.compiled[1].rc.evaluate(oracles.beta[i]),
                        index.compiled[2].rc.evaluate(oracles.beta[i]),
                    ],
                }
            ).collect::<Vec<_>>();
            [evl[0].clone(), evl[1].clone(), evl[2].clone()]
        };

        let x_hat_evals =
            [ x_hat.evaluate(oracles.beta[0])
            , x_hat.evaluate(oracles.beta[1])
            , x_hat.evaluate(oracles.beta[2]) ];

        oracles.x_hat = x_hat_evals;

        for i in 0..3 {
            fr_sponge.absorb_evaluations(&x_hat_evals[i], &evals[i]);
        }

        oracles.polys = fr_sponge.challenge();
        oracles.evals = fr_sponge.challenge();

        // construct the proof
        // --------------------------------------------------------------------

        let mut polys : Vec<(DensePolynomial<Fr<G>>, Option<usize>)> = prev_challenges.iter().map(|(chals, _comm)| {
            let s0 = product(chals.iter().map(|x| *x) ).inverse().unwrap();
            let chal_squareds : Vec<Fr<G>> = chals.iter().map(|x| x.square()).collect();
            let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(s0, &chal_squareds));
            (b, None)
        }).collect();

        polys.extend(
            vec!
            [
                (x_hat.clone(), None),
                (w.clone(),  None),
                (za.clone(), None),
                (zb.clone(), None),
                (h1.clone(), None),
                (h2.clone(), None),
                (h3.clone(), None),
                (index.compiled[0].row.clone(), None),
                (index.compiled[1].row.clone(), None),
                (index.compiled[2].row.clone(), None),
                (index.compiled[0].col.clone(), None),
                (index.compiled[1].col.clone(), None),
                (index.compiled[2].col.clone(), None),
                (index.compiled[0].val.clone(), None),
                (index.compiled[1].val.clone(), None),
                (index.compiled[2].val.clone(), None),
                (index.compiled[0].rc.clone(), None),
                (index.compiled[1].rc.clone(), None),
                (index.compiled[2].rc.clone(), None),
                (g1.clone(), Some(index.domains.h.size()-1)),
                (g2.clone(), Some(index.domains.h.size()-1)),
                (g3.clone(), Some(index.domains.k.size()-1)),
            ]);

        let proof = index.srs.get_ref().open::<EFqSponge>
            (
                &polys,
                &oracles.beta.to_vec(),
                oracles.polys,
                oracles.evals,
                fq_sponge_before_evaluations,
                rng
            )?;

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
            proof, 

            // polynomial evaluations
            evals,

            // prover's scalars
            sigma2,
            sigma3,

            // public part of the witness
            public,
            prev_challenges,
        })
    }

    // This function computes polynomials for the first sumchek protocol
    //     RETURN: prover's H1 & G1 polynomials
    pub fn sumcheck_1_compute
    (
        index: &Index<G>,
        ra: &DensePolynomial<Fr<G>>,
        zm: &[DensePolynomial<Fr<G>>; 3],
        z: &DensePolynomial<Fr<G>>,
        oracles: &RandomOracles<Fr<G>>
    ) -> Result<(DensePolynomial<Fr<G>>, DensePolynomial<Fr<G>>), ProofError>
    {
        // precompute Lagrange polynomial denominators
        let mut lagrng: Vec<Fr<G>> = index.domains.h.elements().map(|elm| {oracles.alpha - &elm}).collect();
        algebra::fields::batch_inversion::<Fr<G>>(&mut lagrng);
        let vanish = index.domains.h.evaluate_vanishing_polynomial(oracles.alpha);

        // compute and return H1 & G1 polynomials
        (0..3).map
        (
            |i|
            {
                let mut ram = Evaluations::<Fr<G>>::from_vec_and_domain(vec![Fr::<G>::zero(); index.domains.h.size()], index.domains.h);
                for val in index.compiled[i].constraints.iter()
                {
                    ram.evals[(val.1).1] += &(vanish * val.0 * &lagrng[(val.1).0]);
                }
                (i, ram)
            }
        ).fold
        (
            DensePolynomial::<Fr<G>>::zero(),
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
        index: &Index<G>,
        ra: &DensePolynomial<Fr<G>>,
        oracles: &RandomOracles<Fr<G>>
    ) -> Result<(DensePolynomial<Fr<G>>, DensePolynomial<Fr<G>>), ProofError>
    {
        // precompute Lagrange polynomial evaluations
        let lagrng = index.domains.h.evaluate_all_lagrange_coefficients(oracles.beta[0]);

        // compute and return H2 & G2 polynomials
        // use the precomputed normalized Lagrange evaluations for interpolation evaluations
        (0..3).map
        (
            |i|
            {
                let mut ramxbval = Evaluations::<Fr<G>>::from_vec_and_domain(vec![Fr::<G>::zero(); index.domains.h.size()], index.domains.h);
                for val in index.compiled[i].constraints.iter()
                {
                    // scale with eta's
                    ramxbval.evals[(val.1).0] += &(*val.0 * &lagrng[(val.1).1] * &[oracles.eta_a, oracles.eta_b, oracles.eta_c][i]);
                }
                ramxbval
            }
        ).fold
        (
            DensePolynomial::<Fr<G>>::zero(),
            |x, y|
            &x + &(&(ra * &y.interpolate()))
        // compute quotient and remainder
        ).divide_by_vanishing_poly(index.domains.h).map_or(Err(ProofError::PolyDivision), |s| Ok(s))
    }

    // This function computes polynomials for the third sumchek protocol
    //     RETURN: prover's H3 & G3 polynomials
    pub fn sumcheck_3_compute
    (
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>
    ) -> Result<(DensePolynomial<Fr<G>>, DensePolynomial<Fr<G>>), ProofError>
    {
        let vanish = index.domains.h.evaluate_vanishing_polynomial(oracles.beta[0]) *
            &index.domains.h.evaluate_vanishing_polynomial(oracles.beta[1]);

        // compute polynomial f3
        let f3 = (0..3).map
        (
            |i|
            {
                Evaluations::<Fr<G>>::from_vec_and_domain
                (
                    {
                        let mut fractions: Vec<Fr<G>> = (0..index.domains.k.size()).map
                        (
                            |j|
                            {
                                (oracles.beta[0] - &index.compiled[i].col_eval_k[j]) *
                                &(oracles.beta[1] - &index.compiled[i].row_eval_k[j])
                            }
                        ).collect();
                        algebra::fields::batch_inversion::<Fr<G>>(&mut fractions);
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
            Evaluations::<Fr<G>>::from_vec_and_domain(vec![Fr::<G>::zero(); index.domains.k.size()], index.domains.k),
            |x, y| &x + &y
        ).interpolate();

        // precompute polynomials (row(X)-oracle1)*(col(X)-oracle2) in evaluation form over domains.b
        let crb: Vec<Vec<Fr<G>>> =
            (0..3).map(|i| index.compiled[i].compute_row_2_col_1(oracles.beta[0], oracles.beta[1])).collect();

        // compute polynomial a
        let a = (0..3).map
        (
            |i|
            {
                Evaluations::<Fr<G>>::from_vec_and_domain
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
            Evaluations::<Fr<G>>::from_vec_and_domain(vec![Fr::<G>::zero(); index.domains.b.size()], index.domains.b),
            |x, y| &x + &y
        ).interpolate();

        // compute polynomial b
        let b = Evaluations::<Fr<G>>::from_vec_and_domain
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
    pub polys: F,
    pub evals: F,
    pub beta: [F; 3],

    pub digest_before_evaluations: F,
    pub x_hat: [F; 3],
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
            polys: F::zero(),
            evals: F::zero(),
            beta: [F::zero(), F::zero(), F::zero()],
            x_hat: [F::zero(), F::zero(), F::zero()],
            digest_before_evaluations: F::zero(),
        }
    }
}
