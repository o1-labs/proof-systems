use super::Proof;

use std::iter;

use circuit_construction::{Constants, Cs, Var};

use ark_ec::AffineCurve;
use ark_ff::{FftField, One, PrimeField, Zero};

use crate::context::Context;
use crate::plonk::proof::{
    eval_polynomial, ScalarChallenge, VarIndex, VarOpen, VarPolyComm, VarProof,
};
use crate::transcript::{Arthur, Msg};

/// Combine multiple openings using a linear combination
/// 
/// QUESTION: why can this not just be one large linear combination,
/// why do we need both xi and r?
fn combined_inner_product<'a, F, C: Cs<F>, const N: usize>(
    cs: &mut C,
    evaluations: &[(Var<F>, Vec<VarOpen<F, N>>)], // evaluation point and openings
    xi: Var<F>,                                   // combinations at powers of x
    r: Var<F>,                                    // new evaluation point
) -> Var<F>
where
    F: FftField + PrimeField,
{
    // accumulated sum: \sum_{j=0} xi^j * term_j
    let mut res = cs.constant(F::zero());

    // xi^i
    let mut xi_i = cs.constant(F::one());

    //
    for (_eval_point, polys) in evaluations {
        for i in 0..N {
            // take the i'th chunk from each polynomial
            let chunks: Vec<Var<F>> = polys.iter().map(|p| p.chunks[i]).collect();

            // evaluate the polynomial with the chunks as coefficients
            let term: Var<F> = eval_polynomial(cs, &chunks, r);

            // res += xi_i * term
            let xi_i_term = cs.mul(xi_i, term);
            res = cs.add(res, xi_i_term);

            // xi_i *= xi
            xi_i = cs.mul(xi_i, xi);

            // QUESTION: the shifting does not seem to be used
            // do we need it? It adds complexity and constraints particularly
            // in the circuit where we need to add a circuit for computing the shift
        }
    }

    res
}

impl<G> VarIndex<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    /// Takes a mutual context with the base-field of the Plonk proof as the "native field"
    /// and generates Fp (base field) and Fr (scalar field)
    /// constraints for the verification of the proof.
    ///
    /// The goal is for this method to look as much as the "clear verifier" in Kimchi.
    ///
    fn verify<CsFp, CsFr, C, T>(
        &self,
        // ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
        ctx: &mut Context<G::BaseField, G::ScalarField, CsFp, CsFr>,
        p_comm: Msg<VarPolyComm<G, 1>>, // commitment to public input
        witness: Option<Proof<G>>,      // witness (a PlonK proof)
    ) where
        CsFp: Cs<G::BaseField>,
        CsFr: Cs<G::ScalarField>,
    {
        // start a new transcript
        let mut tx = Arthur::new(ctx);

        // create proof instance (with/without witness)
        let proof = VarProof::new(witness);

        //~ 2. Absorb commitment to the public input polynomial
        let p_comm = tx.recv(ctx, p_comm);

        //~ 3. Absorb commitments to the registers / witness columns
        let w_comm = tx.recv(ctx, proof.commitments.w_comm);

        //~ 6. Sample $\beta$
        let beta: Var<G::BaseField> = tx.challenge(ctx);

        //~ 7. Sample $\gamma$
        let gamma: Var<G::BaseField> = tx.challenge(ctx);

        //~ 8. If using lookup, absorb the commitment to the aggregation lookup polynomial.
        /*self.commitments.lookup.iter().for_each(|l| {
            fq_sponge.absorb_g(&l.aggreg.unshifted);
        });
        */

        //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
        let z_comm = tx.recv(ctx, proof.commitments.z_comm);

        //~ 10. Sample $\alpha'$
        let alpha_chal: ScalarChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha: ScalarChallenge<G::ScalarField> = ctx.pass(alpha_chal);
        let alpha: Var<G::ScalarField> = ctx.flip(|ctx| alpha.to_field(ctx));

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        // CHANGE: Happens at deserialization time (it is an array).

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        let t_comm = tx.recv(ctx, proof.commitments.t_comm);

        //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$)
        let zeta_chal: ScalarChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta: ScalarChallenge<G::ScalarField> = ctx.pass(zeta_chal);
        let zeta: Var<G::ScalarField> = ctx.flip(|ctx| zeta.to_field(ctx));

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        //~     Absorb over the foreign field

        // Enforce constraints on other side
        let (evals, ft_eval, v_chal, v) = ctx.flip(|ctx| {
            tx.flip(|tx| {
                //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
                //~     - the public polynomial
                //~     - z
                //~     - generic selector
                //~     - poseidon selector
                //~     - the 15 register/witness
                //~     - 6 sigmas evaluations (the last one is not evaluated)
                let evals = tx.recv(ctx, proof.evals);

                //~ 20. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
                let ft_eval1 = tx.recv(ctx, proof.ft_eval1);

                //~ 21. Sample $v'$ with the Fr-Sponge.
                let v_chal: ScalarChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                let v: Var<G::ScalarField> = v_chal.to_field(ctx);

                //~ 23. Sample $u'$ with the Fr-Sponge.
                let u_chal: ScalarChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                let u = u_chal.to_field(ctx);

                // prepare some often used values
                let zetaw = ctx.mul(zeta, self.domain.group_gen);

                // TODO: this should be included in transcript!
                let prev_zeta = proof.prev_challenges.eval_h(ctx.cs(), zeta);
                let prev_zetaw = proof.prev_challenges.eval_h(ctx.cs(), zetaw);

                //~ 25. Create a list of all polynomials that have an evaluation proof.
                let powers_of_eval_points_for_chunks = [
                    ctx.pow(zeta, self.max_poly_size as u64),
                    ctx.pow(zetaw, self.max_poly_size as u64),
                ];

                // compute ft_eval0 (from gate/row constraints)
                let ft_eval0 = unimplemented!();

                // compute the combined inner product:
                // the batching of all the openings
                let combined_inner_product = {
                    // evaluations at \zeta
                    let polys_z = iter::empty()
                        .chain(unimplemented!()) // prev_challenges
                        .chain(iter::once(&ft_eval0)) // ft_eval0
                        .chain(evals.z.iter());

                    // evaluations at \zeta \omega
                    let polys_zw = iter::empty()
                        .chain(unimplemented!()) // prev_challenges
                        .chain(iter::once(&ft_eval1)) // ft_eval1
                        .chain(evals.zw.iter());

                    // combine with xi = v, r = u
                    combined_inner_product(
                        ctx.cs(),
                        vec![
                            (zeta, polys_z.cloned().collect()),
                            (zetaw, polys_zw.cloned().collect()),
                        ],
                        v, // xi
                        u, // r
                    )
                };

                (evals, ft_eval0, v_chal, v)
            })
        });
    }
}
