/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve, Zero, One};
use ff_fft::{DensePolynomial, DenseOrSparsePolynomial, Evaluations, Radix2EvaluationDomain as D};
use commitment_dlog::commitment::{CommitmentField, CommitmentCurve, PolyComm, OpeningProof, b_poly_coefficients, product};
use oracle::{FqSponge, utils::PolyUtils, rndoracle::ProofError, sponge::ScalarChallenge};
use plonk_circuits::scalars::{ProofEvaluations, RandomOracles};
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

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

impl<G: CommitmentCurve> ProverProof<G> where G::ScalarField : CommitmentField
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
        prev_challenges: Vec< (Vec<Fr<G>>, PolyComm<G>) >,
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
        let l = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.l.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let r = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.r.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);
        let o = &Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(index.cs.gates.iter().map(|gate| witness[gate.wires.o.0]).collect(), index.cs.domain.d1).interpolate()
            + &DensePolynomial::rand(1, &mut OsRng).mul_by_vanishing_poly(index.cs.domain.d1);

        // commit to the l, r, o wire values
        let l_comm = index.srs.get_ref().commit(&l, None);
        let r_comm = index.srs.get_ref().commit(&r, None);
        let o_comm = index.srs.get_ref().commit(&o, None);

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.get_ref().commit(&p, None).unshifted);
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

        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.unshifted);
        oracles.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.alpha = oracles.alpha_chal.to_field(&index.srs.get_ref().endo_r);
        let mut alpha = oracles.alpha;
        let alpha = (0..4).map(|_| {alpha *= &oracles.alpha; alpha}).collect::<Vec<_>>();

        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&l, &r, &o, &z);

        // compute quotient polynomial

        // generic constraints contribution
        let (gen4, genp) = index.cs.gnrc_quot(&lagrange, &p);

        // poseidon constraints contribution
        let (pos4, pos8, posp) = index.cs.psdn_quot(&lagrange, &index.cs.fr_sponge_params, &alpha);

        // variable base scalar multiplication constraints contribution
        let (mul4, mul8) = index.cs.vbmul_quot(&lagrange, &alpha);

        // group endomorphism optimised variable base scalar multiplication constraints contribution
        let (emul4, emul8) = index.cs.endomul_quot(&lagrange, &alpha);

        // EC addition constraints contribution
        let (eca4, eca8) = index.cs.ecad_quot(&lagrange, &alpha);

        // permutation check contribution
        let perm = index.cs.perm_quot(&lagrange, &oracles);

        // collect contribution evaluations
        let t4 = &(&gen4 + &pos4) + &(&eca4 + &(&mul4 + &emul4));
        let t8 = &(&pos8 + &(&eca8 + &(&mul8 + &emul8))) + &perm;

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &(&genp + &posp)).
            divide_by_vanishing_poly(index.cs.domain.d1).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        // permutation boundary condition check contribution
        let (bnd, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
                &DensePolynomial::from_coefficients_slice(&[-Fr::<G>::one(), Fr::<G>::one()]).into()).
                map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        t += &bnd.scale(alpha[0]);

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, Some(index.max_quot_size));

        // absorb the polycommitments into the argument and sample zeta
        let max_t_size = (index.max_quot_size + index.max_poly_size - 1) / index.max_poly_size;
        let dummy = G::of_coordinates(Fq::<G>::zero(), Fq::<G>::zero());
        fq_sponge.absorb_g(&t_comm.unshifted);
        fq_sponge.absorb_g(&vec![dummy; max_t_size - t_comm.unshifted.len()]);
        {
            let s = t_comm.shifted.unwrap();
            if s.is_zero() {
                fq_sponge.absorb_g(&[dummy])
            } else {
                fq_sponge.absorb_g(&[s])
            }
        };

        oracles.zeta_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.zeta = oracles.zeta_chal.to_field(&index.srs.get_ref().endo_r);

        // evaluate the polynomials

        let evlp = [oracles.zeta, oracles.zeta * &index.cs.domain.d1.group_gen];
        let evals = evlp.iter().map
        (
            |e| ProofEvaluations::<Vec<Fr<G>>>
            {
                l : l.eval(*e, index.max_poly_size),
                r : r.eval(*e, index.max_poly_size),
                o : o.eval(*e, index.max_poly_size),
                z : z.eval(*e, index.max_poly_size),
                t : t.eval(*e, index.max_poly_size),

                sigma1: index.cs.sigmam[0].eval(*e, index.max_poly_size),
                sigma2: index.cs.sigmam[1].eval(*e, index.max_poly_size),

                f: Vec::new(),
            }
        ).collect::<Vec<_>>();
        let mut evals = [evals[0].clone(), evals[1].clone()];

        let evlp1 = [evlp[0].pow(&[index.max_poly_size as u64]), evlp[1].pow(&[index.max_poly_size as u64])];
        let e = &evals.iter().zip(evlp1.iter()).map
        (
            |(es, &e1)| ProofEvaluations::<Fr<G>>
            {
                l: DensePolynomial::eval_polynomial(&es.l, e1),
                r: DensePolynomial::eval_polynomial(&es.r, e1),
                o: DensePolynomial::eval_polynomial(&es.o, e1),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                t: DensePolynomial::eval_polynomial(&es.t, e1),

                sigma1: DensePolynomial::eval_polynomial(&es.sigma1, e1),
                sigma2: DensePolynomial::eval_polynomial(&es.sigma2, e1),

                f: Fr::<G>::zero(),
            }
        ).collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        let f =
            &(&(&(&(&index.cs.gnrc_lnrz(&e[0]) +
            &index.cs.psdn_lnrz(&e, &index.cs.fr_sponge_params, &alpha)) +
            &index.cs.ecad_lnrz(&e, &alpha)) +
            &index.cs.vbmul_lnrz(&e, &alpha)) +
            &index.cs.endomul_lnrz(&e, &alpha)) +
            &index.cs.perm_lnrz(&e, &z, &oracles);

        evals[0].f = f.eval(evlp[0], index.max_poly_size);
        evals[1].f = f.eval(evlp[1], index.max_poly_size);

        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge =
        {
            let mut s = EFrSponge::new(index.cs.fr_sponge_params.clone());
            s.absorb(&fq_sponge.digest());
            s
        };
        let p_eval = if p.is_zero() {[Vec::new(), Vec::new()]}
            else {[vec![p.evaluate(evlp[0])], vec![p.evaluate(evlp[1])]]};
        for i in 0..2 {fr_sponge.absorb_evaluations(&p_eval[i], &evals[i])}

        // query opening scaler challenges
        oracles.v_chal = fr_sponge.challenge();
        oracles.v = oracles.v_chal.to_field(&index.srs.get_ref().endo_r);
        oracles.u_chal = fr_sponge.challenge();
        oracles.u = oracles.u_chal.to_field(&index.srs.get_ref().endo_r);

        // construct the proof
        // --------------------------------------------------------------------
        let polys = prev_challenges.iter().map(|(chals, _comm)| {
            let s0 = product(chals.iter().map(|x| *x)).inverse().unwrap();
            let chal_squareds : Vec<Fr<G>> = chals.iter().map(|x| x.square()).collect();
            let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(s0, &chal_squareds));
            b
        }).collect::<Vec<_>>();

        let mut polynoms = polys.iter().map(|p| (p, None)).collect::<Vec<_>>();
        polynoms.extend(
            vec!
            [
                (&p, None),
                (&l, None),
                (&r, None),
                (&o, None),
                (&z, None),
                (&t, Some(index.max_quot_size)),
                (&f, None),
                (&index.cs.sigmam[0], None),
                (&index.cs.sigmam[1], None),
            ]);

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
                polynoms,
                &evlp.to_vec(),
                oracles.v,
                oracles.u,
                fq_sponge_before_evaluations,
                &mut OsRng
            ),
            evals,
            public,
            prev_challenges,
        })
    }
}
