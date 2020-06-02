/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use oracle::FqSponge;
use oracle::rndoracle::ProofError;
pub use super::index::{VerifierIndex as Index};
pub use super::prover::{ProverProof, RandomOracles, ProofEvaluations};
use algebra::{Field, AffineCurve};
use ff_fft::DensePolynomial;
use crate::plonk_sponge::{FrSponge};
use commitment_dlog::commitment::{CommitmentCurve, Utils};
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

impl<G: CommitmentCurve> ProverProof<G>
{
    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     rng: randomness source context
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
        let mut batch = proofs.iter().map
        (
            |proof|
            {
                let (fq_sponge, oracles) = proof.oracles::<EFqSponge, EFrSponge>(index);
                let zeta1 = oracles.zeta.pow(&[index.max_poly_size as u64]);
                let zeta2 = oracles.zeta.pow(&[index.domain.size]);
                let zetaw = oracles.zeta * &index.domain.group_gen;
                let zetaw1 = zetaw.pow(&[index.max_poly_size as u64]);
                let alpsq = oracles.alpha.square();
                let bz = oracles.beta * &oracles.zeta;

                // evaluate committed polynoms
                let e = ProofEvaluations::<Fr<G>>
                {
                    l : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].l, zeta1),
                    r : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].r, zeta1),
                    o : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].o, zeta1),
                    z : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].z, zeta1),
                    t : DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].t, zeta1),

                    ql: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].ql, zeta1),
                    qr: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].qr, zeta1),
                    qo: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].qo, zeta1),
                    qm: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].qm, zeta1),
                    qc: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].qc, zeta1),

                    sigma:
                    [
                        DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].sigma[0], zeta1),
                        DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].sigma[1], zeta1),
                        DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].sigma[2], zeta1),
                    ]
                };

                // evaluate lagrange polynoms
                let mut lagrange = (0..proof.public.len()).zip(index.domain.elements()).map(|(_,w)| oracles.zeta - &w).collect::<Vec<_>>();
                algebra::fields::batch_inversion::<Fr<G>>(&mut lagrange);
                lagrange.iter_mut().for_each(|l| *l *= &(zeta2 - &Fr::<G>::one()));

                // check quotient polynomial evaluation consistency
                let t =
                    e.l*&e.r*&e.qm + &(e.l*&e.ql) + &(e.r*&e.qr) + &(e.o*&e.qo) + &e.qc -
                        &(lagrange.iter().zip(proof.public.iter()).zip(index.domain.elements()).
                            map(|((l, p), w)| *l * p * &w).fold(Fr::<G>::zero(), |x, y| x + &y) * &index.domain.size_inv) +
                    &((e.l + &bz + &oracles.gamma) *
                        &(e.r + &(bz * &index.r) + &oracles.gamma) *
                        &(e.o + &(bz * &index.o) + &oracles.gamma) *
                        &e.z * &oracles.alpha) -
                    &((e.l + &(oracles.beta * &e.sigma[0]) + &oracles.gamma) *
                        &(e.r + &(oracles.beta * &e.sigma[1]) + &oracles.gamma) *
                        &(e.o + &(oracles.beta * &e.sigma[2]) + &oracles.gamma) *
                        &DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[1].z, zetaw1) *
                        &oracles.alpha) +
                    &((e.z - &Fr::<G>::one()) * &lagrange[0] * &alpsq);
                
                if t != e.t * &(zeta2 - &Fr::<G>::one()) {return Err(ProofError::ProofVerification)}

                Ok
                ((
                    fq_sponge.clone(),
                    vec![oracles.zeta, zetaw],
                    oracles.v,
                    oracles.u,
                    vec!
                    [
                        (&proof.l_comm, proof.evals.iter().map(|e| &e.l).collect::<Vec<_>>(), None),
                        (&proof.r_comm, proof.evals.iter().map(|e| &e.r).collect::<Vec<_>>(), None),
                        (&proof.o_comm, proof.evals.iter().map(|e| &e.o).collect::<Vec<_>>(), None),
                        (&proof.z_comm, proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None),
                        (&proof.t_comm, proof.evals.iter().map(|e| &e.t).collect::<Vec<_>>(), Some(3*index.domain.size()+3)),

                        (&index.ql_comm,  proof.evals.iter().map(|e| &e.ql).collect::<Vec<_>>(), None),
                        (&index.qr_comm,  proof.evals.iter().map(|e| &e.qr).collect::<Vec<_>>(), None),
                        (&index.qo_comm,  proof.evals.iter().map(|e| &e.qo).collect::<Vec<_>>(), None),
                        (&index.qm_comm,  proof.evals.iter().map(|e| &e.qm).collect::<Vec<_>>(), None),
                        (&index.qc_comm,  proof.evals.iter().map(|e| &e.qc).collect::<Vec<_>>(), None),

                        (&index.sigma_comm[0], proof.evals.iter().map(|e| &e.sigma[0]).collect::<Vec<_>>(), None),
                        (&index.sigma_comm[1], proof.evals.iter().map(|e| &e.sigma[1]).collect::<Vec<_>>(), None),
                        (&index.sigma_comm[2], proof.evals.iter().map(|e| &e.sigma[2]).collect::<Vec<_>>(), None),
                    ],
                    &proof.proof
                ))
            }
        ).collect::<Result<Vec<_>, _>>()?;

        match index.srs.get_ref().verify::<EFqSponge>(group_map, &mut batch, &mut OsRng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>,
        EFrSponge: FrSponge<Fr<G>>,
       >
    (
        &self,
        index: &Index<G>
    ) -> (EFqSponge, RandomOracles<Fr<G>>)
    {
        let mut oracles = RandomOracles::<Fr<G>>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input, l, r, o polycommitments into the argument
        fq_sponge.absorb_fr(&self.public);
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
        oracles.zeta = fq_sponge.challenge();
        // query opening scaler challenges
        oracles.v = fq_sponge.challenge();
        oracles.u = fq_sponge.challenge();

        (fq_sponge, oracles)
    }
}
