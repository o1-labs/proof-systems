use super::{Proof};

use std::iter;

use circuit_construction::{Constants, Cs, Var};

use ark_ec::AffineCurve;
use ark_ff::{FftField, Zero, One, PrimeField};

use crate::context::{Context};
use crate::transcript::{Arthur, Msg};
use crate::plonk::proof::{VarProof, VarOpen, eval_polynomial, ScalarChallenge, VarPolyComm, VarIndex};

///
/// N: number of chunks in polynomial
/// 
/// - evaluations: (x, () )
fn combined_inner_product<'a, F, C: Cs<F>, I, const N: usize>(
    cs: &mut C,
    evaluations: I, // evaluation point and openings
    xi: Var<F>, // combinations at powers of x
    r: Var<F>, // new evaluation point
) -> Var<F> where
    F: FftField + PrimeField,
    I: Iterator<Item = (Var<F>, Vec<VarOpen<F, N>>)>,
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



impl <G> VarIndex<G> where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField {

    /// Takes a mutual context with the base-field of the Plonk proof as the "native field"
    /// and generates Fp (base field) and Fr (scalar field)
    /// constraints for the verification of the proof.
    ///
    ///
    fn verify<CsFp, CsFr, C, T>(
        &self,
        // ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
        ctx: &mut Context<G::BaseField, G::ScalarField, CsFp, CsFr>,
        p_comm: Msg<VarPolyComm<G, 1>>,  // commitment to public input
        witness: Option<Proof<G>>, // witness (a PlonK proof)
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
                let ft_eval = tx.recv(ctx, proof.ft_eval1);

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
                
                //~ 25. Create a list of all polynomials that have an evaluation proof.
                let powers_of_eval_points_for_chunks = [
                    ctx.pow(zeta, self.max_poly_size as u64),
                    ctx.pow(zetaw, self.max_poly_size as u64),
                ];

                let combined_inner_product = {

                    // first the evaluations from the accumulator
                    let polys = iter::empty();

                    // then the ft evaluations
                    let polys = polys.chain(iter::empty());

                    // lastly evaluations from the proof
                    let polys = polys.chain(evals.z.iter());
                   
                    

                    

                    // combined_inner_product(ctx.cs(), unimplemented!(), v, u)
                };


                // aggregate_inner_product::<G>(v_chal, u);

                (evals, ft_eval, v_chal, v)
            })
        });
    }
}

