/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve, Zero, One, UniformRand};
use ff_fft::{DensePolynomial, DenseOrSparsePolynomial, Evaluations, Radix2EvaluationDomain as D};
use commitment_dlog::commitment::{CommitmentField, CommitmentCurve, PolyComm, OpeningProof, b_poly_coefficients, product};
use oracle::{FqSponge, utils::PolyUtils, rndoracle::ProofError, sponge::ScalarChallenge};
use plonk_circuits::{scalars::{ProofEvaluations, RandomOracles}, wires::COLUMNS};
pub use super::{index::Index, range};
use crate::plonk_sponge::{FrSponge};
use array_init::array_init;
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve>
{
    // polynomial commitments
    pub w_comm: [PolyComm<G>; COLUMNS],
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
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>
    (
        group_map: &G::Map,
        witness: &[Vec::<Fr<G>>; COLUMNS],
        index: &Index<G>,
        prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
    )
    -> Result<Self, ProofError>
    {
        let n = index.cs.domain.d1.size as usize;
        for w in witness.iter() {if w.len() != n {return Err(ProofError::WitnessCsInconsistent)}};

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0][0..index.cs.public].to_vec();
        let p = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(public.clone(), index.cs.domain.d1).interpolate();

        // compute witness polynomials
        let w: [DensePolynomial<Fr<G>>; COLUMNS] = array_init(|i| Evaluations::<Fr<G>,
            D<Fr<G>>>::from_vec_and_domain(witness[i].clone(), index.cs.domain.d1).interpolate());

        // commit to the wire values
        let w_comm: [PolyComm<G>; COLUMNS] = array_init(|i| index.srs.get_ref().commit(&w[i], None));

        // absorb the wire polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.get_ref().commit(&p, None).unshifted);
        w_comm.iter().for_each(|c| fq_sponge.absorb_g(&c.unshifted));

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute permutation polynomial

        let mut z = vec![Fr::<G>::one(); n];
        (0..n-3).for_each
        (
            |j| z[j+1] = witness.iter().zip(index.cs.sigmal1.iter()).map
            (
                |(w, s)| w[j] + &(s[j] * &oracles.beta) + &oracles.gamma
            ).fold(Fr::<G>::one(), |x, y| x * y)
        );
        algebra::fields::batch_inversion::<Fr<G>>(&mut z[1..=n-3]);
        (0..n-3).for_each
        (
            |j|
            {
                let x = z[j];
                z[j+1] *= witness.iter().zip(index.cs.shift.iter()).map
                (
                    |(w, s)| w[j] + &(index.cs.sid[j] * &oracles.beta * s) + &oracles.gamma
                ).fold(x, |z, y| z * y)
            }
        );

        if z[n-3] != Fr::<G>::one() {return Err(ProofError::ProofCreation)};
        z[n-2] = Fr::<G>::rand(&mut OsRng);
        z[n-1] = Fr::<G>::rand(&mut OsRng);
        let z = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(z, index.cs.domain.d1).interpolate();

        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.unshifted);
        oracles.alpha = fq_sponge.challenge();
        let mut alpha = oracles.alpha;
        let alpha = (0..34).map(|_| {alpha *= &oracles.alpha; alpha}).collect::<Vec<_>>();

        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&w, &z);

        // compute quotient polynomial

        // permutation
        let perm = index.cs.perm_quot(&lagrange, &oracles);
        // generic
        let (gen, genp) = index.cs.gnrc_quot(&lagrange, &p);
        // poseidon
        let (pos4, pos8, posp) = index.cs.psdn_quot(&lagrange, &index.cs.fr_sponge_params, &alpha[range::PSDN]);
        // EC addition
        let add = index.cs.ecad_quot(&lagrange, &alpha[range::ADD]);
        // EC doubling
        let double = index.cs.double_quot(&lagrange, &alpha[range::DBL]);
        // endoscaling
        let emul4 = index.cs.endomul_quot(&lagrange, &alpha[range::ENDML]);
        // unpacking
        let pack = index.cs.pack_quot(&lagrange, &alpha[range::PACK]);
        // scalar multiplication
        let mul4 = index.cs.vbmul_quot(&lagrange, &alpha[range::MUL]);
        // unpacking scalar multiplication
        let mul8 = index.cs.vbmulpck_quot(&lagrange, &alpha[range::ENDML]);

        // collect contribution evaluations
        let t4 = &add + &(&mul4 + &(&emul4 + &(&pack + &(&pos4 + &gen))));
        let t8 = &perm + &(&mul8 + &(&pos8 + &double));

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &(&genp + &posp)).
            divide_by_vanishing_poly(index.cs.domain.d1).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        // permutation boundary condition check
        let (bnd1, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
                &DensePolynomial::from_coefficients_slice(&[-Fr::<G>::one(), Fr::<G>::one()]).into()).
                map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        let (bnd2, res) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
                &DensePolynomial::from_coefficients_slice(&[-index.cs.sid[n-3], Fr::<G>::one()]).into()).
                map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        t += &(&bnd1.scale(alpha[0]) + &bnd2.scale(alpha[1]));

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, Some(index.max_quot_size));

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&t_comm.unshifted);
        oracles.zeta = ScalarChallenge(fq_sponge.challenge()).to_field(&index.srs.get_ref().endo_r);

        // evaluate the polynomials
        let evlp = [oracles.zeta, oracles.zeta * &index.cs.domain.d1.group_gen];
        let evals = evlp.iter().map
        (
            |e| ProofEvaluations::<Vec<Fr<G>>>
            {
                s: array_init(|i| index.cs.sigmam[0..COLUMNS-1][i].eval(*e, index.max_poly_size)),
                w: array_init(|i| w[i].eval(*e, index.max_poly_size)),
                z: z.eval(*e, index.max_poly_size),
                t: t.eval(*e, index.max_poly_size),
                f: Vec::new(),
            }
        ).collect::<Vec<_>>();
        let mut evals = [evals[0].clone(), evals[1].clone()];

        let evlp1 = [evlp[0].pow(&[index.max_poly_size as u64]), evlp[1].pow(&[index.max_poly_size as u64])];
        let e = &evals.iter().zip(evlp1.iter()).map
        (
            |(es, &e1)| ProofEvaluations::<Fr<G>>
            {
                s: array_init(|i| DensePolynomial::eval_polynomial(&es.s[i], e1)),
                w: array_init(|i| DensePolynomial::eval_polynomial(&es.w[i], e1)),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                t: DensePolynomial::eval_polynomial(&es.t, e1),
                f: Fr::<G>::zero(),
            }
        ).collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        let f =
            &(&(&(&(&(&(&(&index.cs.gnrc_lnrz(&e[0]) +
            &index.cs.psdn_lnrz(&e, &index.cs.fr_sponge_params, &alpha[range::PSDN])) +
            &index.cs.ecad_lnrz(&e, &alpha[range::ADD])) +
            &index.cs.double_lnrz(&e, &alpha[range::DBL])) +
            &index.cs.endomul_lnrz(&e, &alpha[range::ENDML])) +
            &index.cs.pack_lnrz(&e, &alpha[range::PACK])) +
            &index.cs.vbmul_lnrz(&e, &alpha[range::MUL])) +
            &index.cs.vbmulpck_lnrz(&e, &alpha[range::MLPCK])) +
            &index.cs.perm_lnrz(&e, &z, &oracles, &alpha[range::PERM]);

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
        oracles.v = fr_sponge.challenge().to_field(&index.srs.get_ref().endo_r);
        oracles.u = fr_sponge.challenge().to_field(&index.srs.get_ref().endo_r);

        // construct the proof
        // --------------------------------------------------------------------
        let polys = prev_challenges.iter().map(|(chals, _comm)| {
            let s0 = product(chals.iter().map(|x| *x)).inverse().unwrap();
            let chal_squareds : Vec<Fr<G>> = chals.iter().map(|x| x.square()).collect();
            let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(s0, &chal_squareds));
            b
        }).collect::<Vec<_>>();

        let mut polynoms = polys.iter().map(|p| (p, None)).collect::<Vec<_>>();
        polynoms.extend(w.iter().map(|w| (w, None)).collect::<Vec<_>>());
        polynoms.extend(
            vec!
            [
                (&z, None),
                (&t, Some(index.max_quot_size)),
                (&f, None),
                (&p, None),
            ]);
        polynoms.extend(index.cs.sigmam[0..COLUMNS-1].iter().map(|w| (w, None)).collect::<Vec<_>>());

        Ok(Self
        {
            w_comm,
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
