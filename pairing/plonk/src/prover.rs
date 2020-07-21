/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use rand_core::OsRng;
use algebra::{Field, PairingEngine, Zero, One};
use ff_fft::{DensePolynomial, DenseOrSparsePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use oracle::{utils::PolyUtils, sponge::{FqSponge, ScalarChallenge}, rndoracle::ProofError};
use plonk_circuits::scalars::{ProofEvaluations, RandomOracles};
use crate::plonk_sponge::FrSponge;
pub use super::index::Index;

#[derive(Clone)]
pub struct ProverProof<E: PairingEngine>
{
    // polynomial commitments
    pub l_comm: E::G1Affine,
    pub r_comm: E::G1Affine,
    pub o_comm: E::G1Affine,
    pub z_comm: E::G1Affine,
    pub tlow_comm: E::G1Affine,
    pub tmid_comm: E::G1Affine,
    pub thgh_comm: E::G1Affine,

    // batched commitment opening proofs
    pub proof1: E::G1Affine,
    pub proof2: E::G1Affine,

    // polynomial evaluations
    pub evals : ProofEvaluations<E::Fr>,

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
        let n = index.cs.domain.d1.size();
        if witness.len() != 3*n {return Err(ProofError::WitnessCsInconsistent)}

        let mut oracles = RandomOracles::<E::Fr>::zero();
        let mut evals = ProofEvaluations::<E::Fr>
        {
            l: E::Fr::zero(),
            r: E::Fr::zero(),
            o: E::Fr::zero(),
            sigma1: E::Fr::zero(),
            sigma2: E::Fr::zero(),
            f: E::Fr::zero(),
            z: E::Fr::zero(),
            t: E::Fr::zero(),
        };

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0..index.cs.public].to_vec();
        let p = -Evaluations::<E::Fr, D<E::Fr>>::from_vec_and_domain(public.clone(), index.cs.domain.d1).interpolate();

        // compute witness polynomials
        let l = &Evaluations::<E::Fr, D<E::Fr>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.l.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let r = &Evaluations::<E::Fr, D<E::Fr>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.r.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let o = &Evaluations::<E::Fr, D<E::Fr>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.o.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);

        // commit to the l, r, o wire values
        let l_comm = index.urs.get_ref().commit(&l)?;
        let r_comm = index.urs.get_ref().commit(&r)?;
        let o_comm = index.urs.get_ref().commit(&o)?;

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_fr(&public);
        fq_sponge.absorb_g(&[l_comm, r_comm, o_comm]);

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute permutation polynomial

        let mut z = vec![E::Fr::one(); n+1];
        z.iter_mut().skip(1).enumerate().for_each
        (
            |(j, x)| *x =
                (witness[j] + &(index.cs.sigmal1[0][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+n] + &(index.cs.sigmal1[1][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+2*n] + &(index.cs.sigmal1[2][j] * &oracles.beta) + &oracles.gamma)
        );
        
        algebra::fields::batch_inversion::<E::Fr>(&mut z[1..=n]);

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

        if z.pop().unwrap() != E::Fr::one() {return Err(ProofError::ProofCreation)};
        let z = Evaluations::<E::Fr, D<E::Fr>>::from_vec_and_domain(z, index.cs.domain.d1).interpolate();
        
        // evaluate witness polynomials over domains
        let lagrange = index.cs.evaluate(&l, &r, &o, &z);

        // commit to z
        let z_comm = index.urs.get_ref().commit(&z)?;

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&[z_comm]);
        oracles.alpha = fq_sponge.challenge();
        let alpsq = oracles.alpha.square();

        // compute quotient polynomial

        // generic constraints contribution
        let (gen2, genp) = index.cs.gnrc_quot(&lagrange, &p);

        // permutation check contribution
        let perm = index.cs.perm_quot(&lagrange, &oracles);

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&gen2.interpolate() + &perm.interpolate()) + &genp).
            divide_by_vanishing_poly(index.cs.domain.d1).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        // premutation boundary condition check contribution
        let (bnd, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[E::Fr::one()])).into(),
                &DensePolynomial::from_coefficients_slice(&[-E::Fr::one(), E::Fr::one()]).into()).
                map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        t += &bnd.scale(alpsq);

        // split t to fit to the commitment
        let tlow: DensePolynomial<E::Fr>;
        let mut tmid = DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]);
        let mut thgh = DensePolynomial::from_coefficients_slice(&[E::Fr::zero()]);
        if t.coeffs.len() <= n {tlow = t}
        else if t.coeffs.len() <= 2*n
        {
            tlow = DensePolynomial::from_coefficients_slice(&t.coeffs[0..n]);
            tmid = DensePolynomial::from_coefficients_slice(&t.coeffs[n..t.coeffs.len()]);
        }
        else
        {
            tlow = DensePolynomial::from_coefficients_slice(&t.coeffs[0..n]);
            tmid = DensePolynomial::from_coefficients_slice(&t.coeffs[n..2*n]);
            thgh = DensePolynomial::from_coefficients_slice(&t.coeffs[2*n..]);
        }

        // commit to tlow, tmid, thgh
        let tlow_comm = index.urs.get_ref().commit(&tlow)?;
        let tmid_comm = index.urs.get_ref().commit(&tmid)?;
        let thgh_comm = index.urs.get_ref().commit(&thgh)?;

        // absorb the polycommitments into the argument and sample zeta
        
        fq_sponge.absorb_g(&[tlow_comm, tmid_comm, thgh_comm]);
        oracles.zeta = ScalarChallenge(fq_sponge.challenge());
        let zeta2 = oracles.zeta.0.pow(&[n as u64]);
        let zeta3 = zeta2.square();

        // evaluate the polynomials
        evals.l = l.evaluate(oracles.zeta.0);
        evals.r = r.evaluate(oracles.zeta.0);
        evals.o = o.evaluate(oracles.zeta.0);
        evals.sigma1 = index.cs.sigmam[0].evaluate(oracles.zeta.0);
        evals.sigma2 = index.cs.sigmam[1].evaluate(oracles.zeta.0);
        evals.z = z.evaluate(oracles.zeta.0 * &index.cs.domain.d1.group_gen);

        // compute linearization polynomial

        let bz = oracles.beta * &oracles.zeta.0;
        let f1 =
            &(&(&(&index.cs.qmm.scale(evals.l*&evals.r) +
            &index.cs.qlm.scale(evals.l)) +
            &index.cs.qrm.scale(evals.r)) +
            &index.cs.qom.scale(evals.o)) +
            &index.cs.qc;
        let f2 =
            z.scale
            (
                (evals.l + &bz + &oracles.gamma) *
                &(evals.r + &(bz * &index.cs.r) + &oracles.gamma) *
                &(evals.o + &(bz * &index.cs.o) + &oracles.gamma) *
                &oracles.alpha +
                &(alpsq * &(zeta2 - &E::Fr::one()) / &(oracles.zeta.0 - &E::Fr::one()))
            );
        let f3 =
            index.cs.sigmam[2].scale
            (
                (evals.l + &(oracles.beta * &evals.sigma1) + &oracles.gamma) *
                &(evals.r + &(oracles.beta * &evals.sigma2) + &oracles.gamma) *
                &(oracles.beta * &evals.z * &oracles.alpha)
            );
        let f = &(&f1 + &f2) - &f3;
        evals.f = f.evaluate(oracles.zeta.0);

        // query opening scaler challenge
        oracles.v = ScalarChallenge(fq_sponge.challenge());

        Ok(Self
        {
            l_comm,
            r_comm,
            o_comm,
            z_comm,
            tlow_comm,
            tmid_comm,
            thgh_comm,
            proof1: index.urs.get_ref().open
            (
                vec!
                [
                    &(&(&tlow + &tmid.scale(zeta2)) + &thgh.scale(zeta3)),
                    &f,
                    &l,
                    &r,
                    &o,
                    &index.cs.sigmam[0],
                    &index.cs.sigmam[1],
                ],
                oracles.v.0,
                oracles.zeta.0
            )?,
            proof2: index.urs.get_ref().open(vec![&z], oracles.v.0, oracles.zeta.0 * &index.cs.domain.d1.group_gen)?,
            evals,
            public
        })
    }
}
