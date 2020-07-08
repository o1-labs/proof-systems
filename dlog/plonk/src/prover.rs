/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve, Zero, One};
use ff_fft::{DensePolynomial, DenseOrSparsePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::{FqSponge, utils::PolyUtils, rndoracle::{ProofError}, poseidon::SPONGE_BOX};
use plonk_circuits::{gate::SPONGE_WIDTH, scalars::{ProofEvaluations, RandomOracles}};
use commitment_dlog::commitment::{QnrField, CommitmentCurve, PolyComm, OpeningProof};
use crate::plonk_sponge::{FrSponge};
pub use super::index::Index;
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

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

impl<G: CommitmentCurve> ProverProof<G> where G::ScalarField : QnrField
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
        let n = index.cs.domain.d1.size as usize;
        if witness.len() != 3*n {return Err(ProofError::WitnessCsInconsistent)}

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0..index.cs.public].to_vec();
        let p = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(public.clone(), index.cs.domain.d1).interpolate();

        // compute witness polynomials
        let l = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.l.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let r = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.r.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let o = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.o.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);

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
                (witness[j] + &(index.cs.sigmal1[0][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+n] + &(index.cs.sigmal1[1][j] * &oracles.beta) + &oracles.gamma) *&
                (witness[j+2*n] + &(index.cs.sigmal1[2][j] * &oracles.beta) + &oracles.gamma)
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
        let z = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(z, index.cs.domain.d1).interpolate() +
            &DensePolynomial::rand(2, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        
        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&l, &r, &o, &z);

        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.unshifted);
        oracles.alpha = fq_sponge.challenge();
        let mut alpha = oracles.alpha;
        let alpha = (0..SPONGE_WIDTH+3).map(|_| {alpha *= &oracles.alpha; alpha}).collect::<Vec<_>>();

        // compute quotient polynomial

        // generic constraints contribution
        let (gen2, genp) = index.cs.gnrc_quot(&lagrange, &p);

        // poseidon constraints contribution
        let (pos2, pos4, posp) = index.cs.psdn_quot(&lagrange, &alpha);

        // EC addition constraints contribution
        let (eca2, eca4) = index.cs.ecad_quot(&lagrange, &alpha);

        // permutation check contribution
        let perm = index.cs.perm_quot(&lagrange, &oracles);

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&(&(&gen2 + &pos2) + &eca2).interpolate() + &(&(&pos4 + &eca4) + &perm).interpolate()) + &(&genp + &posp)).
            divide_by_vanishing_poly(index.cs.domain.d1).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        // permutation boundary condition check contribution
        let (bnd, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
                &DensePolynomial::from_coefficients_slice(&[-Fr::<G>::one(), Fr::<G>::one()]).into()).
                map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        t += &bnd.scale(alpha[0]);
        t.coeffs.resize(SPONGE_BOX * (n+2) - SPONGE_BOX, Fr::<G>::zero());

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, Some(SPONGE_BOX * (n+2) - SPONGE_BOX));

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&t_comm.unshifted);
        oracles.zeta = fq_sponge.challenge();

        // evaluate the polynomials

        let evlp = [oracles.zeta, oracles.zeta * &index.cs.domain.d1.group_gen];
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

        let evlp1 =
        [
            oracles.zeta.pow(&[index.max_poly_size as u64]),
            (oracles.zeta * &index.cs.domain.d1.group_gen).pow(&[index.max_poly_size as u64])
        ];
        let e = (0..2).map
        (
            |i| ProofEvaluations::<Fr<G>>
            {
                l: DensePolynomial::eval_polynomial(&evals[i].l, evlp1[i]),
                r: DensePolynomial::eval_polynomial(&evals[i].r, evlp1[i]),
                o: DensePolynomial::eval_polynomial(&evals[i].o, evlp1[i]),
                z: DensePolynomial::eval_polynomial(&evals[i].z, evlp1[i]),
                t: DensePolynomial::eval_polynomial(&evals[i].t, evlp1[i]),
    
                sigma1: DensePolynomial::eval_polynomial(&evals[i].sigma1, evlp1[i]),
                sigma2: DensePolynomial::eval_polynomial(&evals[i].sigma2, evlp1[i]),
    
                f: Fr::<G>::zero(),
            }
        ).collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        let f =
            &(&(&index.cs.gnrc_lnrz(&e[0]) +
            &index.cs.psdn_lnrz(&e, &alpha)) +
            &index.cs.ecad_lnrz(&e, &alpha)) -
            &index.cs.perm_lnrz(&e, &oracles);

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
                    (&t, Some(SPONGE_BOX * (n+2) - SPONGE_BOX)),
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
