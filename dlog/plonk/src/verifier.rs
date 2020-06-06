/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use oracle::FqSponge;
use oracle::rndoracle::ProofError;
pub use super::index::{VerifierIndex as Index};
pub use super::prover::{ProverProof, RandomOracles, ProofEvaluations};
use algebra::{Field, PrimeField, AffineCurve, VariableBaseMSM, ProjectiveCurve, Zero, One};
use ff_fft::{DensePolynomial, EvaluationDomain};
use crate::plonk_sponge::{FrSponge};
use commitment_dlog::commitment::{CommitmentCurve, Utils, PolyComm};
use rand_core::OsRng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

impl<G: CommitmentCurve> ProverProof<G>
{
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
        let mut f_comm = vec![PolyComm::<G>{unshifted: Vec::new(), shifted: None}; proofs.len()];
        let mut batch = proofs.iter().zip(f_comm.iter_mut()).map
        (
            |(proof, f_comm)|
            {
                let (fq_sponge, oracles) = proof.oracles::<EFqSponge, EFrSponge>(index);
                let zeta1 = oracles.zeta.pow(&[index.max_poly_size as u64]);
                let zeta2 = oracles.zeta.pow(&[index.domain.size]);
                let zetaw = oracles.zeta * &index.domain.group_gen;
                let alpsq = oracles.alpha.square();
                let bz = oracles.beta * &oracles.zeta;

                // evaluate committed polynoms
                let evals = ProofEvaluations::<Fr<G>>
                {
                    l: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].l, zeta1),
                    r: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].r, zeta1),
                    o: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].o, zeta1),
                    z: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[1].z, zetaw.pow(&[index.max_poly_size as u64])),
                    t: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].t, zeta1),
                    f: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].f, zeta1),
                    sigma1: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].sigma1, zeta1),
                    sigma2: DensePolynomial::<Fr<G>>::eval_polynomial(&proof.evals[0].sigma2, zeta1),
                };

                // evaluate lagrange polynoms
                let mut lagrange = (0..proof.public.len()).zip(index.domain.elements()).map(|(_,w)| oracles.zeta - &w).collect::<Vec<_>>();
                algebra::fields::batch_inversion::<Fr<G>>(&mut lagrange);
                lagrange.iter_mut().for_each(|l| *l *= &(zeta2 - &Fr::<G>::one()));

                let ab = (evals.l + &(oracles.beta * &evals.sigma1) + &oracles.gamma) *
                    &(evals.r + &(oracles.beta * &evals.sigma2) + &oracles.gamma) *
                    &oracles.alpha * &evals.z;

                // compute linearization polynomial commitment
                *f_comm = PolyComm::<G>
                {
                    shifted: None,
                    unshifted:
                    {
                        let p = [&index.qm_comm, &index.ql_comm, &index.qr_comm, &index.qo_comm, &index.qc_comm, &proof.z_comm, &index.sigma_comm[2]];
                        let n = p.iter().map(|c| c.unshifted.len()).max().unwrap();
                        let s =
                            [
                                evals.l * &evals.r, evals.l, evals.r, evals.o, Fr::<G>::one(),
                                (
                                    (evals.l + &bz + &oracles.gamma) *
                                    &(evals.r + &(bz * &index.r) + &oracles.gamma) *
                                    &(evals.o + &(bz * &index.o) + &oracles.gamma) * &oracles.alpha +
                                    &(lagrange[0] * &alpsq)
                                ),
                                -ab * &oracles.beta,
                            ];
                        (0..n).map
                        (
                            |i|
                            {
                                let mut points = Vec::new();
                                let mut scalars = Vec::new();
                                p.iter().zip(s.iter()).for_each
                                    (|(p, s)| if i < p.unshifted.len() {points.push(p.unshifted[i]); scalars.push(s.into_repr())});
                                VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine()
                            }
                        ).collect()
                    }
                };

                // check quotient polynomial evaluation consistency
                if
                    (evals.f - &(ab * &(evals.o + &oracles.gamma)) -
                    &(lagrange.iter().zip(proof.public.iter()).zip(index.domain.elements()).map
                        (|((l, p), w)| *l * p * &w).fold(Fr::<G>::zero(), |x, y| x + &y) * &index.domain.size_inv) -
                    &(lagrange[0] * &alpsq))
                !=
                    evals.t * &(zeta2 - &Fr::<G>::one()) {return Err(ProofError::ProofVerification)}

                // prepare for the opening proof verification
                Ok
                ((
                    fq_sponge,
                    vec![oracles.zeta, zetaw],
                    oracles.v,
                    oracles.u,
                    vec!
                    [
                        (&proof.l_comm, proof.evals.iter().map(|e| &e.l).collect::<Vec<_>>(), None),
                        (&proof.r_comm, proof.evals.iter().map(|e| &e.r).collect::<Vec<_>>(), None),
                        (&proof.o_comm, proof.evals.iter().map(|e| &e.o).collect::<Vec<_>>(), None),
                        (&proof.z_comm, proof.evals.iter().map(|e| &e.z).collect::<Vec<_>>(), None),
                        (&proof.t_comm, proof.evals.iter().map(|e| &e.t).collect::<Vec<_>>(), Some(3*index.domain.size()+6)),

                        (f_comm, proof.evals.iter().map(|e| &e.f).collect::<Vec<_>>(), None),

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
