use super::Proof;

use std::iter;

use circuit_construction::{Constants, Cs, Var, generic};

use kimchi::circuits::wires::{COLUMNS, PERMUTS};

use ark_ec::AffineCurve;
use ark_ff::{FftField, One, PrimeField, Zero};

use crate::context::Context;
use crate::expr::{Assignments, Evaluator};
use crate::plonk::index::Index;
use crate::plonk::misc::{eval_const_poly};
use crate::plonk::proof::{eval_polynomial, VarEvaluation, VarEvaluations, VarProof};
use crate::plonk::types::{ScalarChallenge, VanishEval, LagrangePoly, VarOpen, VarPolyComm};
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

// public input is a polynomial in Lagrange basis
// (but where accessing an evaluation of the poly requires absorption)
struct PublicInput<G>(LagrangePoly<G::ScalarField>)
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField;

impl <G> PublicInput<G>  where
G: AffineCurve,
G::BaseField: FftField + PrimeField {
    pub fn eval<C: Cs<G::ScalarField>>(
        &self, 
        cs: &mut C, 
        x: Var<G::ScalarField>,
        pnt: &VanishEval<G::ScalarField>,
    ) -> Msg<VarOpen<G::ScalarField,1>> {
        self.0.eval(cs, x, pnt).into()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
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
    zh_zeta: &VanishEval<G::ScalarField>,
    eval: &VarEvaluations<G::ScalarField>,
    gamma: Var<G::ScalarField>,
    beta: Var<G::ScalarField>,
    zeta: Var<G::ScalarField>,
    alpha: &[Var<G::ScalarField>; 3],
)  -> VarOpen<G::ScalarField, 1> {
    // evaluate the (constant) ZKP polynomial at \zeta, i.e. zkpm(\zeta)
    let zkp = eval_const_poly(cs, &self.constant.zkpm, zeta);

    // row constraints: 
    // 1. gates satified
    // 2. public input
    let term_row = {
        

    };

    // shuffle proof related constraints
    let term_recurrence = {
        // $\prod_i \left((\beta s_i) + w_i + \gamma\right)$
        let before: Var<_> = {
            let mut prod = (0..PERMUTS - 1).map(|i| {
                let si = eval.zeta.s[i].clone().into();
                let wi = eval.zeta.w[i].clone().into();

                // \beta * s
                let tmp = cs.mul(beta, si);

                // + w[i]
                let tmp = cs.add(tmp, wi);

                // + \gamma
                cs.add(tmp, gamma)
            }).collect::<Vec<Var<_>>>();

            // last column is handled differently:
            // linearlization optimization
            prod.push({
                cs.add(eval.zeta.w[PERMUTS - 1].clone().into(), gamma)
            });

            // * z(\zeta\omega)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zetaw.z.clone().into());
            product(cs, prod.into_iter())
        };

        // $\prod_i left((\zeta  \beta shift_i) + w_i + \gamma\right)$
        let after: Var<_> = {
            let mut prod = (0..PERMUTS).map(|i| {
                let ki = self.constant.shift[i];
                let wi = eval.zeta.w[i].clone().into();

                // beta * zeta * shift;
                let tmp = generic!(cs, (beta, zeta) : { ? = beta * ki * zeta });

                // + w[i]
                let tmp = cs.add(tmp, wi);

                // + \gamma
                cs.add(tmp, gamma)
            }).collect::<Vec<Var<_>>>();

            // * z(\zeta)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zeta.z.clone().into());
            product(cs, prod.into_iter())
        };

        // (<before> - <after>)
        let diff = cs.sub(before, after);

        // * zkp(\zeta)
        cs.mul(diff, zkp)
    };

    // boundary condition on permutation proof
    // this is somewhat more complicated that in the original plonk due to the zkp polynomial
    let term_boundary = {
        let one = G::ScalarField::one();
        let zhz = zh_zeta.as_ref().clone();
        let omega = self.constant.domain.group_gen;
        let eval0_z: Var<G::ScalarField> = eval.zeta.z.clone().into();

        let numerator = {
            // $a_1 = \alpha_1 \cdot Z_H(\zeta) \cdot (\zeta - \omega)$
            let t1 = generic!(cs, (zhz, zeta) : { ? = zhz * (zeta - omega) } ); 
            let a1 = cs.mul(t1, alpha[1]);
            
            // $a_2 = alpha_2 \cdot Z_H(\zeta) \cdot (\zeta - 1)$
            let t2 = generic!(cs, (zhz, zeta) : { ? = zhz * (zeta - one) } ); 
            let a2 = cs.mul(t2, alpha[2]);

            // $b = a_1 + a_2$
            let b = cs.add(a1, a2);

            // $b \cdot (1 - z(\zeta))$
            generic!(cs, (b, eval0_z) : { ? = b * (one - eval0_z) })
        };

        // (\zeta - \omega) * (\zeta - 1)
        let denominator = generic!(
            cs, 
            (zeta) : { ? = (zeta - omega) * (zeta - one) }
        );

        //
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
        p_comm: Msg<VarPolyComm<G, 1>>,
        inputs: &PublicInput<G>, // commitment to public input
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
        assert_eq!(inputs.len(), self.constant.public_input_size);

        //~ 1. absorb index

        //~ 1. absorb accumulator commitments
        let acc_comms = tx.recv(ctx, proof.prev_challenges.comm);

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
                // zetaw = zeta * \omega
                let omega = self.constant.domain.group_gen;
                let zetaw = generic!({ ctx.cs() }, (zeta) : { ? = omega * zeta } );
              
                // note that $Z_H(\zeta) = Z_H(\zeta \omega)$: we only need to eval one
                let zh_zeta = VanishEval::new(ctx.cs(), &self.constant.domain, zeta);

                //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
                //~     - the public polynomial
                //~     - z
                //~     - generic selector
                //~     - poseidon selector
                //~     - the 15 register/witness
                //~     - 6 sigmas evaluations (the last one is not evaluated)

                // absorb $\zeta$ evaluations
                let p_zeta = inputs.eval(ctx.cs(), zeta, &zh_zeta); 
                let p_zeta = tx.recv(ctx, p_zeta);
                let e_zeta = tx.recv(ctx, proof.evals.zeta);

                // absorb $\zeta\omega$ evaluations 
                let p_zetaw = inputs.eval(ctx.cs(), zetaw, &zh_zeta);
                let p_zetaw = tx.recv(ctx, p_zetaw);
                let e_zetaw = tx.recv(ctx, proof.evals.zetaw);

                let evals = VarEvaluations {
                    zeta: e_zeta,
                    zetaw: e_zetaw
                };

                // compute ft_eval0
                let ft_eval0 = unimplemented!();

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
