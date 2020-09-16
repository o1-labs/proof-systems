/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

pub use super::prover::ProverProof;
pub use super::index::VerifierIndex as Index;
use oracle::{FqSponge, rndoracle::ProofError, utils::PolyUtils, sponge::ScalarChallenge};
use plonk_circuits::{scalars::{ProofEvaluations, RandomOracles}, constraints::ConstraintSystem};
use commitment_dlog::commitment::{CommitmentField, CommitmentCurve, PolyComm};
use ff_fft::{DensePolynomial, EvaluationDomain};
use algebra::{Field, AffineCurve, Zero, One};
use crate::plonk_sponge::FrSponge;
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct CachedValues<Fs> {
    pub zeta1: Fs,
    pub zetaw: Fs,
    pub alpha: Vec<Fs>,
}

impl<G: CommitmentCurve> ProverProof<G> where G::ScalarField : CommitmentField
{

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    // This setup is partial; the values `u` and `v` are initialized to zero so
    // that the evaluations it uses can be cached for use in the verification.
    pub fn setup_oracles
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        &self,
        index: &Index<G>,
        p_comm: &PolyComm<G>,
    ) -> (EFqSponge, RandomOracles<Fr<G>>)
    {
        // Run random oracle argument to sample verifier oracles
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());
        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_g(&p_comm.unshifted);
        fq_sponge.absorb_g(&self.l_comm.unshifted);
        fq_sponge.absorb_g(&self.r_comm.unshifted);
        fq_sponge.absorb_g(&self.o_comm.unshifted);
        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();
        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&self.z_comm.unshifted);
        oracles.alpha = fq_sponge.challenge();
        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&self.t_comm.unshifted);
        oracles.zeta = ScalarChallenge(fq_sponge.challenge()).to_field(&index.srs.get_ref().endo_r);

        (fq_sponge, oracles)
    }

    pub fn gen_cached_values
    (
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>
    ) -> CachedValues<Fr<G>>
    {
        let n = index.domain.size;
        let zeta1 = oracles.zeta.pow(&[n]);
        let zetaw = oracles.zeta * &index.domain.group_gen;
        let mut alpha = oracles.alpha;
        let alpha = (0..4).map(|_| {alpha *= &oracles.alpha; alpha}).collect::<Vec<_>>();

        CachedValues {zeta1, zetaw, alpha}
    }

    pub fn p_eval
    (
        &self,
        index: &Index<G>,
        oracles: &RandomOracles<Fr<G>>,
        cached_values: &CachedValues<Fr<G>>,
        p_eval: &mut[Vec<Fr<G>>; 2],
    ) -> ()
    {
        let n = index.domain.size;

        // compute Lagrange base evaluation denominators
        let w = (0..self.public.len()).zip(index.domain.elements()).map(|(_,w)| w).collect::<Vec<_>>();
        let mut lagrange = w.iter().map(|w| oracles.zeta - w).collect::<Vec<_>>();
        (0..self.public.len()).zip(w.iter()).for_each(|(_,w)| lagrange.push(cached_values.zetaw - w));
        algebra::fields::batch_inversion::<Fr<G>>(&mut lagrange);

        // evaluate public input polynomials
        // NOTE: this works only in the case when the poly segment size is not smaller than that of the domain
        if self.public.len() > 0
        {
            (*p_eval)[0] = vec![(self.public.iter().zip(lagrange.iter()).
                zip(index.domain.elements()).map(|((p, l), w)| -*l * p * &w).
                fold(Fr::<G>::zero(), |x, y| x + &y)) * &(cached_values.zeta1 - &Fr::<G>::one()) * &index.domain.size_inv];
            (*p_eval)[1] = vec![(self.public.iter().zip(lagrange[self.public.len()..].iter()).
                zip(index.domain.elements()).map(|((p, l), w)| -*l * p * &w).
                fold(Fr::<G>::zero(), |x, y| x + &y)) * &index.domain.size_inv * &(cached_values.zetaw.pow(&[n as u64]) - &Fr::<G>::one())];
        }
    }

    // This function constructs the values `u` and `v` in the random oracle.
    pub fn finalize_oracles
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        &self,
        index: &Index<G>,
        p_eval: &[Vec<Fr<G>>; 2],
        fq_sponge: &EFqSponge,
        oracles: &mut RandomOracles<Fr<G>>,
    ) -> ()
    {
        let mut fr_sponge =
        {
            let mut s = EFrSponge::new(index.fr_sponge_params.clone());
            s.absorb(&fq_sponge.clone().digest());
            s
        };

        for i in 0..2 {fr_sponge.absorb_evaluations(&p_eval[i], &self.evals[i])}

        // query opening scalar challenges
        oracles.v = fr_sponge.challenge().to_field(&index.srs.get_ref().endo_r);
        oracles.u = fr_sponge.challenge().to_field(&index.srs.get_ref().endo_r);
    }

    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
         EFrSponge: FrSponge<Fr<G>>,
        >
    (
        group_map: &G::Map,
        proofs: &Vec<ProverProof<G>>,
        index: &Index<G>,
    ) -> Result<bool, ProofError>
    {
        let n = index.domain.size;
        let mut p_eval = vec![[Vec::<Fr<G>>::new(), Vec::<Fr<G>>::new()]; proofs.len()];
        let mut p_comm = vec![PolyComm::<G>{unshifted: Vec::new(), shifted: None}; proofs.len()];
        let mut f_comm = p_comm.clone();
        let mut batch = proofs.iter().zip(f_comm.iter_mut().zip(p_comm.iter_mut().zip(p_eval.iter_mut()))).map
        (
            |(proof, (f_comm, (p_comm, p_eval)))|
            {
                // commit to public input polynomial
                *p_comm = PolyComm::<G>::multi_scalar_mul
                    (&index.srs.get_ref().lgr_comm.iter().map(|l| l).collect(), &proof.public.iter().map(|s| -*s).collect());

                let (mut fq_sponge, mut oracles) = proof.setup_oracles::<EFqSponge, EFrSponge>(index, p_comm);
                // prepare some often used values
                let cached_values = ProverProof::<G>::gen_cached_values(index, &oracles);
                proof.p_eval(index, &oracles, &cached_values, p_eval);
                proof.finalize_oracles::<EFqSponge, EFrSponge>(index, p_eval, &mut fq_sponge, &mut oracles);

                // evaluate committed polynoms
                let evlp =
                [
                    oracles.zeta.pow(&[index.max_poly_size as u64]),
                    cached_values.zetaw.pow(&[index.max_poly_size as u64])
                ];

                let evals = (0..2).map
                (
                    |i| ProofEvaluations::<Fr<G>>
                    {
                        l: DensePolynomial::eval_polynomial(&proof.evals[i].l, evlp[i]),
                        r: DensePolynomial::eval_polynomial(&proof.evals[i].r, evlp[i]),
                        o: DensePolynomial::eval_polynomial(&proof.evals[i].o, evlp[i]),
                        z: DensePolynomial::eval_polynomial(&proof.evals[i].z, evlp[i]),
                        t: DensePolynomial::eval_polynomial(&proof.evals[i].t, evlp[i]),
                        f: DensePolynomial::eval_polynomial(&proof.evals[i].f, evlp[i]),
                        sigma1: DensePolynomial::eval_polynomial(&proof.evals[i].sigma1, evlp[i]),
                        sigma2: DensePolynomial::eval_polynomial(&proof.evals[i].sigma2, evlp[i]),
                    }
                ).collect::<Vec<_>>();

                // compute linearization polynomial commitment
                let p = vec!
                [
                    // permutation polynomial commitments
                    &proof.z_comm, &index.sigma_comm[2],
                    // generic constraint polynomial commitments
                    &index.qm_comm, &index.ql_comm, &index.qr_comm, &index.qo_comm, &index.qc_comm,
                    // poseidon constraint polynomial commitments
                    &index.psm_comm, &index.rcm_comm[0], &index.rcm_comm[1], &index.rcm_comm[2],
                    // EC addition constraint polynomial commitments
                    &index.add_comm,
                    // EC variable base scalar multiplication constraint polynomial commitments
                    &index.mul1_comm, &index.mul2_comm,
                    // group endomorphism optimised variable base scalar multiplication constraint polynomial commitments
                    &index.emul1_comm, &index.emul2_comm, &index.emul3_comm,
                ];

                // permutation linearization scalars
                let mut s = ConstraintSystem::perm_scalars(&evals, &oracles, (index.r, index.o), n);
                // generic constraint/permutation linearization scalars
                s.extend(&ConstraintSystem::gnrc_scalars(&evals[0]));
                // poseidon constraint linearization scalars
                s.extend(&ConstraintSystem::psdn_scalars(&evals, &cached_values.alpha));
                // EC addition constraint linearization scalars
                s.extend(&ConstraintSystem::ecad_scalars(&evals, &cached_values.alpha));
                // EC variable base scalar multiplication constraint linearization scalars
                s.extend(&ConstraintSystem::vbmul_scalars(&evals, &cached_values.alpha));
                // group endomorphism optimised variable base scalar multiplication constraint linearization scalars
                s.extend(&ConstraintSystem::endomul_scalars(&evals, index.srs.get_ref().endo_r, &cached_values.alpha));

                *f_comm = PolyComm::multi_scalar_mul(&p, &s);

                // check linearization polynomial evaluation consistency
                if
                    (evals[0].f + &(if p_eval[0].len() > 0 {p_eval[0][0]} else {Fr::<G>::zero()})
                    -
                    ((evals[0].l + &(oracles.beta * &evals[0].sigma1) + &oracles.gamma) *
                    &(evals[0].r + &(oracles.beta * &evals[0].sigma2) + &oracles.gamma) *
                    (evals[0].o + &oracles.gamma) * &evals[1].z * &oracles.alpha)
                    -
                    evals[0].t * &(cached_values.zeta1 - &Fr::<G>::one()))
                    *
                    &(oracles.zeta - &Fr::<G>::one())
                !=
                    (cached_values.zeta1 - &Fr::<G>::one()) * &cached_values.alpha[0]
                {return Err(ProofError::ProofVerification)}

                // prepare for the opening proof verification
                Ok((
                    fq_sponge,
                    vec![oracles.zeta, cached_values.zetaw],
                    oracles.v,
                    oracles.u,
                    vec!
                    [
                        (&proof.l_comm, proof.evals.iter().map(|e| &e.l).collect::<Vec<_>>(), None),
                        (&proof.r_comm, proof.evals.iter().map(|e| &e.r).collect::<Vec<_>>(), None),
                        (&proof.o_comm, proof.evals.iter().map(|e| &e.o).collect::<Vec<_>>(), None),
                        (&proof.z_comm, proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None),
                        (&proof.t_comm, proof.evals.iter().map(|e| &e.t).collect::<Vec<_>>(), Some(index.max_quot_size)),

                        (f_comm, proof.evals.iter().map(|e| &e.f).collect::<Vec<_>>(), None),
                        (p_comm, p_eval.iter().map(|e| e).collect::<Vec<_>>(), None),

                        (&index.sigma_comm[0], proof.evals.iter().map(|e| &e.sigma1).collect::<Vec<_>>(), None),
                        (&index.sigma_comm[1], proof.evals.iter().map(|e| &e.sigma2).collect::<Vec<_>>(), None),
                    ],
                    &proof.proof
                ))
            }
        ).collect::<Result<Vec<_>, _>>()?;

        // verify the opening proofs
        match index.srs.get_ref().verify::<EFqSponge>(group_map, &mut batch, &mut OsRng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }
}
