use super::Proof;

use std::iter;

use circuit_construction::{Constants, Cs, Var};

use kimchi::circuits::wires::{COLUMNS, PERMUTS};

use ark_ec::AffineCurve;
use ark_ff::{FftField, One, PrimeField, Zero};

use crate::context::Context;
use crate::expr::{Assignments, Evaluator};
use crate::plonk::index::Index;
use crate::plonk::misc::{eval_const_poly};
use crate::plonk::proof::{eval_polynomial, VarEvaluations, VarProof};
use crate::plonk::types::{ScalarChallenge, LagrangePoly, VarOpen, VarPolyComm};
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

fn powers<F: FftField + PrimeField>(base: Var<F>, num: usize) -> Vec<Var<F>> {
    unimplemented!()
}

// TODO: add unit test for compat with combined_inner_product from Kimchi using Witness Generator

fn product<F: FftField + PrimeField, I: Iterator<Item = Var<F>>, C: Cs<F>>(cs: &mut C, mut prod: I) -> Var<F> {
    let mut tmp = prod.next().unwrap();
    for term in prod {
        tmp = cs.mul(term, tmp);
    }
    tmp
}



struct PublicInput<G> 
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    comm: Msg<VarPolyComm<G, 1>>,
    inputs: LagrangePoly<G::ScalarField>,
}


impl<G> Index<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    /// Note: we do not care about the evaluation of ft(\zeta \omega),
    /// however we need it for aggregation, therefore we simply allow the prover to provide it.
    /// 
    /// TODO: Optimize heavily using generic gates
fn compute_ft_eval0<C: Cs<G::ScalarField>>  (
    &self,
    cs: &mut C,
    eval: VarEvaluations<G::ScalarField>, // evaluations at zeta
    gamma: Var<G::ScalarField>,
    beta: Var<G::ScalarField>,
    zeta: Var<G::ScalarField>,
    alpha: &[Var<G::ScalarField>; 3],
)  -> VarOpen<G::ScalarField, 1> {
    // compute \zeta^{|<\omega>|}:
    // \zeta shifted "one-beyond" the length of the domain
    let w = cs.constant(self.constant.domain.group_gen); // omega
    let one = cs.constant(G::ScalarField::one());

    // evaluate vanishing polynomial at \zeta
     // this is called zeta1 (for some reason) in Kimchi
    let zeta1 = cs.pow(zeta, self.constant.domain.size);

    let zeta1m1 = cs.sub(zeta1, one);

    // evaluate the (constant) ZKP polynomial at \zeta, i.e. zkpm(\zeta)
    let zkp = eval_const_poly(cs, &self.constant.zkpm, zeta);

    // row constraints: gates satified, public input restricted
    let term_row = {
        

    };

    // shuffle proof related constraints
    let term_shuffle = {
        // shuffle proof "base": recurrence for Bayer-Groth-style product
        let base: Var<_> = {
            // \prod_i (\zeta * \beta * shift[i]) + w[i] + \gamma
            let mut prod = (0..PERMUTS).map(|i| {
                // TODO: optimize using generic gate
                // let t = generic!(cs, (beta, zeta), { beta * zeta * s });
                let s = cs.constant(self.constant.shift[i]);
                let t = cs.mul(beta, zeta);
                let t = cs.mul(t, s);

                let t = cs.add(t, eval.zeta.w[i].clone().into());
                let t = cs.add(t, gamma.into());
                t
            }).collect::<Vec<Var<_>>>();

            // * z(\zeta)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zeta.z.clone().into());
            product(cs, prod.into_iter())
        };

        // shuffle proof "step": recurrence for Bayer-Groth-style product
        let step: Var<_> = {
            // \prod_i (\beta * s[i]) + w[i] + \gamma
            let mut prod = (0..PERMUTS - 1).map(|i| {
                // (\beta * s[i]) + w[i] + \gamma
                let t = cs.mul(beta, eval.zeta.s[i].clone().into());
                let t = cs.add(t, eval.zeta.w[i].clone().into());
                let t = cs.add(t, gamma.into());
                t
            }).collect::<Vec<Var<_>>>();

            // last column is handled differently:
            // linearlization optimization
            prod.push({
                cs.add(eval.zeta.w[PERMUTS - 1].clone().into(), gamma)
            });

            // * z(\zeta\omega)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zetaw.z.into());
            product(cs, prod.into_iter())
        };

        // <base> - <step>
        let diff = cs.sub(base, step);

        // multiply by zkp(\zeta) for hiding
        let tmp = cs.mul(diff, zkp);

        // multiply by alpha power to seperate
        let tmp = cs.mul(tmp, alpha[0]);
        tmp
    };

    //
    let term_b = {
        let numerator = {
            // (zeta1m1 * alpha[1] * (zeta - w))
            let t1 = cs.mul(zeta1m1, alpha[1]);
            let t2 = cs.sub(zeta, w);
            let a1 = cs.mul(t1, t2);
            
            // (zeta1m1 * alpha[2] * (zeta - one))
            let t1 = cs.mul(zeta1m1, alpha[2]);
            let t2 = cs.sub(zeta, one);
            let a2 = cs.mul(t1, t2);

            //   (zeta1m1 * alpha[1] * (zeta - w))
            // + (zeta1m1 * alpha[2] * (zeta - one))
            let b = cs.add(a1, a2);

            //
            let t1 = cs.sub(one, eval.zeta.z.into());
            cs.mul(t1, b)
        };

        // (\zeta - \omega) * (\zeta - 1)
        let denominator = {
            // this is a single generic gate!
            let t1 = cs.sub(zeta, w);
            let t2 = cs.sub(zeta, one);
            cs.mul(t1, t2)
        };

        cs.div(numerator, denominator)
    };
    

    //
    // let zeta1m1 = zeta1 - ScalarField::<G>::one();


    unimplemented!()
}


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
        p: PublicInput<G>, // commitment to public input
        witness: Option<Proof<G>>,      // witness (a PlonK proof)
    ) where
        CsFp: Cs<G::BaseField>,
        CsFr: Cs<G::ScalarField>,
    {
        // start a new transcript
        let mut tx = Arthur::new(ctx);

        // create proof instance (with/without witness)
        let proof: VarProof<_, 2> = VarProof::new(witness);

        // sanity checks
        assert_eq!(p.inputs.size(), self.constant.public_input_size);

        //~ 1. absorb index

        //~ 1. absorb accumulator commitments
        let acc_comms = tx.recv(ctx, proof.prev_challenges.comm);

        //~ 2. Absorb commitment to the public input polynomial
        let p_comm = tx.recv(ctx, p.comm);

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
        let alpha: Var<G::ScalarField> = ctx.flip(|ctx| alpha.to_field(ctx.cs()));

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        // CHANGE: Happens at deserialization time (it is an array).

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        let t_comm = tx.recv(ctx, proof.commitments.t_comm);

        //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$)
        let zeta_chal: ScalarChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta: ScalarChallenge<G::ScalarField> = ctx.pass(zeta_chal);
        let zeta: Var<G::ScalarField> = ctx.flip(|ctx| zeta.to_field(ctx.cs()));

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        //~     Absorb over the foreign field

        // Enforce constraints on other side
        let (evals, ft_eval, v_chal) = ctx.flip(|ctx| {
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

                // receive accumulator challenges (IPA challenges)
                let acc_chals = tx.recv(ctx, proof.prev_challenges.chal);

                //~ 21. Sample $v'$ with the Fr-Sponge.
                let v_chal: ScalarChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                let v: Var<G::ScalarField> = v_chal.to_field(ctx.cs());

                //~ 23. Sample $u'$ with the Fr-Sponge.
                let u_chal: ScalarChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                let u = u_chal.to_field(ctx.cs());

                // compute \zeta\omega = \zeta * \omega
                // TODO: optimize can be done using a single gate
                let omega = ctx.constant(self.constant.domain.group_gen);
                let zetaw = ctx.mul(zeta, omega);

                // evaluate the h(X) polynomials from accumulators at \zeta
                let hs_z: Vec<_> = acc_chals
                    .iter()
                    .map(|acc| acc.eval_h(ctx.cs(), zeta))
                    .collect();

                // evaluate the h(X) polynomials from accumulators at \zeta\omega
                let hs_zw: Vec<_> = acc_chals
                    .iter()
                    .map(|acc| acc.eval_h(ctx.cs(), zetaw))
                    .collect();

                //~ 25. Create a list of all polynomials that have an evaluation proof.
                /*
                let powers_of_eval_points_for_chunks = [
                    ctx.pow(zeta, self.max_poly_size as u64),
                    ctx.pow(zetaw, self.max_poly_size as u64),
                ];
                */

                // compute ft_eval0 (from gate/row constraints)
                let ft_eval0 = unimplemented!(); // self.compute_ft_eval0(zeta); // how to do this using Var<F>, PolishToken does not support it

                // compute the combined inner product:
                // the batching of all the openings
                let combined_inner_product = {
                    // evaluations at \zeta
                    let evals_z = iter::empty()
                        .chain(hs_z) // h(\zeta)
                        .chain(iter::once(unimplemented!())) // p_eval(\zeta)
                        .chain(iter::once(ft_eval0)) // ft_eval0
                        .chain(evals.zeta.iter().cloned()); // openings from proof

                    // evaluations at \zeta * \omega
                    let evals_zw = iter::empty()
                        .chain(hs_zw) // h(\zeta\omega)
                        .chain(iter::once(unimplemented!())) // p_eval(\zeta\omega)
                        .chain(iter::once(ft_eval1)) // ft_eval1
                        .chain(evals.zetaw.iter().cloned()); // openings from proof

                    // compute a randomized combinations of all the openings
                    // with xi = v, r = u
                    combined_inner_product(
                        ctx.cs(),
                        &vec![
                            (zeta, evals_z.collect()),   // (eval point, openings)
                            (zetaw, evals_zw.collect()), // (eval point, openings)
                        ],
                        v, // xi
                        u, // r
                    )
                };

                (evals, ft_eval0, v_chal)
            })
        });
    }
}
