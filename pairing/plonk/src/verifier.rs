/********************************************************************************************

This source file implements zk-proof batch verifier functionality.

*********************************************************************************************/

use rand_core::OsRng;
use oracle::rndoracle::ProofError;
use crate::index::{VerifierIndex as Index};
pub use super::prover::{ProverProof, RandomOracles};
use algebra::{Field, PrimeField, PairingEngine, ProjectiveCurve, VariableBaseMSM};
use crate::plonk_sponge::FrSponge;
use oracle::sponge::FqSponge;

impl<E: PairingEngine> ProverProof<E>
{
    // This function verifies the batch of zk-proofs
    //     proofs: vector of Plonk proofs
    //     index: Index
    //     RETURN: verification status
    pub fn verify
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        proofs: &Vec<ProverProof<E>>,
        index: &Index<E>
    ) -> Result<bool, ProofError>
    {
        let mut batch = Vec::new();
        for proof in proofs.iter()
        {
            let oracles = proof.oracles::<EFqSponge, EFrSponge>(index)?;
            let zeta2 = oracles.zeta.pow(&[index.domain.size]);
            let alpsq = oracles.alpha.square();
            let bz = oracles.beta * &oracles.zeta;
            let ab = (proof.evals.a + &(oracles.beta * &proof.evals.sigma1) + &oracles.gamma) *
                &(proof.evals.b + &(oracles.beta * &proof.evals.sigma2) + &oracles.gamma) *
                &oracles.alpha * &proof.evals.z;

            // compute quotient polynomial commitment
            let t_comm = VariableBaseMSM::multi_scalar_mul
            (
                &[proof.tlow_comm, proof.tmid_comm, proof.thgh_comm],
                &[E::Fr::one().into_repr(), zeta2.into_repr(), zeta2.square().into_repr()]
            ).into_affine();

            // evaluate lagrange polynoms
            let mut lagrange = (0..proof.public.len()).zip(index.domain.elements()).map(|(_,w)| oracles.zeta - &w).collect::<Vec<_>>();
            algebra::fields::batch_inversion::<E::Fr>(&mut lagrange);
            lagrange.iter_mut().for_each(|l| *l *= &(zeta2 - &E::Fr::one()));

            // compute quotient polynomial evaluation
            let t =
                (proof.evals.r - &(ab * &(proof.evals.c + &oracles.gamma)) -
                &(lagrange.iter().zip(proof.public.iter()).zip(index.domain.elements()).
                    map(|((l, p), w)| *l * p * &w).fold(E::Fr::zero(), |x, y| x + &y) * &index.domain.size_inv) -
                &(lagrange[0] * &alpsq)) / &(zeta2 - &E::Fr::one());

            // compute linearization polynomial commitment
            let r_comm = VariableBaseMSM::multi_scalar_mul
            (
                &[index.qm_comm, index.ql_comm, index.qr_comm, index.qo_comm, index.qc_comm, proof.z_comm, -index.sigma_comm[2]],
                &[
                    (proof.evals.a * &proof.evals.b).into_repr(), proof.evals.a.into_repr(),
                    proof.evals.b.into_repr(), proof.evals.c.into_repr(), E::Fr::one().into_repr(),
                    (
                        (proof.evals.a + &bz + &oracles.gamma) *
                        &(proof.evals.b + &(bz * &index.r) + &oracles.gamma) *
                        &(proof.evals.c + &(bz * &index.o) + &oracles.gamma) * &oracles.alpha +
                        &(lagrange[0] * &alpsq)
                    ).into_repr(),
                    (ab * &oracles.beta).into_repr(),
                ]
            ).into_affine();

            // prepare for the opening proof verification
            batch.push
            ((
                oracles.zeta,
                oracles.v,
                vec!
                [
                    (t_comm,                t, None),
                    (r_comm,                proof.evals.r, None),
                    (proof.a_comm,          proof.evals.a, None),
                    (proof.b_comm,          proof.evals.b, None),
                    (proof.c_comm,          proof.evals.c, None),
                    (index.sigma_comm[0],   proof.evals.sigma1, None),
                    (index.sigma_comm[1],   proof.evals.sigma2, None),
                ],
                proof.proof1
            ));
            batch.push
            ((
                oracles.zeta * &index.domain.group_gen,
                oracles.v,
                vec![(proof.z_comm, proof.evals.z, None)],
                proof.proof2
            ));
        }

        // verify the opening proofs
        match index.urs.verify(&batch, &mut OsRng)
        {
            false => Err(ProofError::OpenProof),
            true => Ok(true)
        }
    }

    // This function queries random oracle values from non-interactive
    // argument context by verifier
    pub fn oracles
        <EFqSponge: FqSponge<E::Fq, E::G1Affine, E::Fr>,
         EFrSponge: FrSponge<E::Fr>,
        >
    (
        &self,
        index: &Index<E>
    ) -> Result<RandomOracles<E::Fr>, ProofError>
    {
        let mut oracles = RandomOracles::<E::Fr>::zero();
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // absorb the public input, a, b, c polycommitments into the argument
        fq_sponge.absorb_fr(&self.public);
        fq_sponge.absorb_g(&[self.a_comm, self.b_comm, self.c_comm]);
        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&[self.z_comm]);
        oracles.alpha = fq_sponge.challenge();

        // absorb the polycommitments into the argument and sample zeta
        fq_sponge.absorb_g(&[self.tlow_comm, self.tmid_comm, self.thgh_comm]);
        oracles.zeta = fq_sponge.challenge();
        // query opening scaler challenge
        oracles.v = fq_sponge.challenge();

        Ok(oracles)
    }
}
