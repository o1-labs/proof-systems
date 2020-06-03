/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve, Zero, One};
use oracle::{FqSponge, rndoracle::{ProofError}};
use ff_fft::{DensePolynomial, DenseOrSparsePolynomial, EvaluationDomain};
use commitment_dlog::commitment::{CommitmentCurve, Utils, PolyComm, OpeningProof};
use crate::plonk_sponge::{FrSponge};
pub use super::index::Index;
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;
 
pub struct RandomOracles<F: Field>
{
    pub beta: F,
    pub gamma: F,
    pub alpha: F,
    pub zeta: F,
    pub v: F,
    pub u: F,
}

#[derive(Clone)]
pub struct ProofEvaluations<Fs> {
    pub l: Fs,
    pub r: Fs,
    pub o: Fs,
    pub z: Fs,
    pub t: Fs,
    pub f: Fs,
    pub sigma1: Fs,
    pub sigma2: Fs,
}

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve>
{
    // polynomial commitments
    pub l_comm: PolyComm<G>,
    pub r_comm: PolyComm<G>,
    pub o_comm: PolyComm<G>,
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,

    // batched commitment opening proof
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    pub evals: [ProofEvaluations<Vec<Fr<G>>>; 2],

    // public part of the witness
    pub public: Vec<Fr<G>>,
}

impl<G: CommitmentCurve> ProverProof<G>
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
        group_map: &G::Map,
        witness: &Vec::<Fr<G>>,
        index: &Index<G>,
    ) 
    -> Result<Self, ProofError>
    {
        let n = index.cs.domain.size();
        if witness.len() != 3*n {return Err(ProofError::WitnessCsInconsistent)}

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0..index.cs.public].to_vec();
        let p = -index.cs.evals_from_coeffs(public.clone()).interpolate();

        let l = &index.cs.evals_from_coeffs(index.cs.gates.iter().map(|gate| witness[gate.l.0]).collect()).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain);
        let r = &index.cs.evals_from_coeffs(index.cs.gates.iter().map(|gate| witness[gate.r.0]).collect()).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain);
        let o = &index.cs.evals_from_coeffs(index.cs.gates.iter().map(|gate| witness[gate.o.0]).collect()).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain);

        // commit to the l, r, o wire values
        let l_comm = index.srs.get_ref().commit(&l, None);
        let r_comm = index.srs.get_ref().commit(&r, None);
        let o_comm = index.srs.get_ref().commit(&o, None);

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_fr(&public);
        fq_sponge.absorb_g(&l_comm.unshifted);
        fq_sponge.absorb_g(&r_comm.unshifted);
        fq_sponge.absorb_g(&o_comm.unshifted);

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute permutation polynomial

        let mut z = vec![Fr::<G>::one(); n+1];
        z.iter_mut().skip(1).enumerate().for_each
        (
            |(j, x)| *x =
                (witness[j] + &(index.cs.sigmal[0][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+n] + &(index.cs.sigmal[1][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+2*n] + &(index.cs.sigmal[2][j] * &oracles.beta) + &oracles.gamma)
        );
        
        algebra::fields::batch_inversion::<Fr<G>>(&mut z[1..=n]);

        (0..n).for_each
        (
            |j|
            {
                let x = z[j];
                z[j+1] *=
                &(x * &(witness[j] + &(index.cs.sid[j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+n] + &(index.cs.sid[j] * &oracles.beta * &index.cs.r) + &oracles.gamma) *&
                (witness[j+2*n] + &(index.cs.sid[j] * &oracles.beta * &index.cs.o) + &oracles.gamma))
            }
        );

        if z.pop().unwrap() != Fr::<G>::one() {return Err(ProofError::ProofCreation)};
        let z = index.cs.evals_from_coeffs(z).interpolate();

        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.unshifted);
        oracles.alpha = fq_sponge.challenge();
        let alpsq = oracles.alpha.square();

        // compute quotient polynomial

        let t1 =
            &(&(&(&(&(&l*&(&r*&index.cs.qm)) +
            &(&l*&index.cs.ql)) +
            &(&r*&index.cs.qr)) +
            &(&o*&index.cs.qo)) +
            &index.cs.qc) + &p;
        let t2 =
            &(&(&(&l + &DensePolynomial::from_coefficients_slice(&[oracles.gamma, oracles.beta])) *
            &(&r + &DensePolynomial::from_coefficients_slice(&[oracles.gamma, oracles.beta*&index.cs.r]))) *
            &(&o + &DensePolynomial::from_coefficients_slice(&[oracles.gamma, oracles.beta*&index.cs.o]))) * &z;
        let t3 =
            &(&(&(&(&l + &DensePolynomial::from_coefficients_slice(&[oracles.gamma])) + &index.cs.sigmam[0].scale(oracles.beta)) *
            &(&(&r + &DensePolynomial::from_coefficients_slice(&[oracles.gamma])) + &index.cs.sigmam[1].scale(oracles.beta))) *
            &(&(&o + &DensePolynomial::from_coefficients_slice(&[oracles.gamma])) + &index.cs.sigmam[2].scale(oracles.beta))) *
            &DensePolynomial::from_coefficients_vec(z.coeffs.iter().zip(index.cs.sid.iter()).
                map(|(z, w)| *z * &w).collect::<Vec<_>>());
        let (t4, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[-Fr::<G>::one(), Fr::<G>::one()]).into()).
            map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let (mut t, res) = (&t1 + &(&t2 - &t3).scale(oracles.alpha)).
            divide_by_vanishing_poly(index.cs.domain).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}
        t += &t4.scale(alpsq);

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, Some(3*n+3));

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&t_comm.unshifted);
        oracles.zeta = fq_sponge.challenge();
        let zeta1 = oracles.zeta.pow(&[index.max_poly_size as u64]);
        let zeta2 = oracles.zeta.pow(&[n as u64]);

        // evaluate the polynomials

        let evlp = [oracles.zeta, oracles.zeta * &index.cs.domain.group_gen];
        let evals = (0..2).map
        (
            |i| ProofEvaluations::<Vec<Fr<G>>>
            {
                l : l.eval(evlp[i], index.max_poly_size),
                r : r.eval(evlp[i], index.max_poly_size),
                o : o.eval(evlp[i], index.max_poly_size),
                z : z.eval(evlp[i], index.max_poly_size),
                t : t.eval(evlp[i], index.max_poly_size),

                sigma1: index.cs.sigmam[0].eval(evlp[i], index.max_poly_size),
                sigma2: index.cs.sigmam[1].eval(evlp[i], index.max_poly_size),

                f: Vec::new(),
            }
        ).collect::<Vec<_>>();
        let mut evals = [evals[0].clone(), evals[1].clone()];

        let e = ProofEvaluations::<Fr<G>>
        {
            l: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].l, zeta1),
            r: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].r, zeta1),
            o: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].o, zeta1),
            z: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[1].z, evlp[1].pow(&[index.max_poly_size as u64])),
            t: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].t, zeta1),

            sigma1: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].sigma1, zeta1),
            sigma2: DensePolynomial::<Fr<G>>::eval_polynomial(&evals[0].sigma2, zeta1),

            f: Fr::<G>::zero(),
        };

        // compute linearisation polynomial

        let bz = oracles.beta * &oracles.zeta;
        let f1 =
            &(&(&(&index.cs.qm.scale(e.l*&e.r) +
            &index.cs.ql.scale(e.l)) +
            &index.cs.qr.scale(e.r)) +
            &index.cs.qo.scale(e.o)) +
            &index.cs.qc;
        let f2 =
            z.scale
            (
                (e.l + &bz + &oracles.gamma) *
                &(e.r + &(bz * &index.cs.r) + &oracles.gamma) *
                &(e.o + &(bz * &index.cs.o) + &oracles.gamma) *
                &oracles.alpha
            );
        let f3 =
            index.cs.sigmam[2].scale
            (
                (e.l + &(oracles.beta * &e.sigma1) + &oracles.gamma) *
                &(e.r + &(oracles.beta * &e.sigma2) + &oracles.gamma) *
                &(oracles.beta * &e.z * &oracles.alpha)
            );
        let f4 = z.scale(alpsq * &(zeta2 - &Fr::<G>::one()) / &(oracles.zeta - &Fr::<G>::one()));
        let f = &(&(&f1 + &f2) - &f3) + &f4;
        evals[0].f = f.eval(evlp[0], index.max_poly_size);
        evals[1].f = f.eval(evlp[1], index.max_poly_size);

        // query opening scaler challenges
        oracles.v = fq_sponge.challenge();
        oracles.u = fq_sponge.challenge();
        let fq_sponge_before_evaluations = fq_sponge.clone();

        Ok(Self
        {
            l_comm,
            r_comm,
            o_comm,
            z_comm,
            t_comm,
            proof: index.srs.get_ref().open
            (
                group_map,
                vec!
                [
                    (&l, None),
                    (&r, None),
                    (&o, None),
                    (&z, None),
                    (&t, Some(3*n+3)),
                    (&f, None),
                    (&index.cs.sigmam[0], None),
                    (&index.cs.sigmam[1], None),
                ],
                &evlp.to_vec(),
                oracles.v,
                oracles.u,
                fq_sponge_before_evaluations,
                &mut OsRng
            ),
            evals,
            public
        })
    }
}

impl<F: Field> RandomOracles<F>
{
    pub fn zero () -> Self
    {
        Self
        {
            beta: F::zero(),
            gamma: F::zero(),
            alpha: F::zero(),
            zeta: F::zero(),
            v: F::zero(),
            u: F::zero(),
        }
    }
}
