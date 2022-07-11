use std::iter;

use circuit_construction::{generic, Constants, Cs, Var};

use kimchi::circuits::expr::Column;
use kimchi::circuits::gate::GateType;
use kimchi::circuits::wires::{COLUMNS, PERMUTS};

use ark_ec::AffineCurve;
use ark_ff::{FftField, One, PrimeField, Zero};

use crate::context::Context;

use crate::expr::{Assignments, Evaluator};

use crate::kimchi::alphas::Alphas;
use crate::kimchi::index::{ConstIndex, Index};
use crate::kimchi::proof::{eval_polynomial, VarEvaluations, VarProof};

use crate::util::{eval_const_poly, var_product};

use crate::types::{
    FieldChallenge, GLVChallenge, LagrangePoly, Scalar, VarEval, VarPoint, VarPolyComm,
    polynomials
};

use crate::transcript::{Arthur, Msg};

fn perm_scalars<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    evals: &VarEvaluations<F>,
    beta: Var<F>,
    gamma: Var<F>,
    alphas: &[Var<F>; 3],
    zkp_zeta: Var<F>,
) -> Var<F> {
    //~ Compute
    //~
    //~ $$
    //~ \begin{align}
    //~ z(\zeta \omega) \beta \alpha^{PERM0} zkpl(\zeta) \cdot \\
    //~ (\gamma + \beta \sigma_0(\zeta) + w_0(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_1(\zeta) + w_1(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_2(\zeta) + w_2(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_3(\zeta) + w_3(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_4(\zeta) + w_4(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_5(\zeta) + w_5(\zeta)) \cdot \\
    //~ \end{align}
    //~$$
    //~

    // first term
    let mut prod = vec![evals.zetaw.z.clone().into(), beta, alphas[0], zkp_zeta];

    // compute for every chunk of the committed permutation
    debug_assert_eq!(evals.zeta.s.len(), PERMUTS - 1);
    prod.extend((0..PERMUTS - 1).map(|i| {
        let si = evals.zeta.s[i].clone().into();
        let wi = evals.zeta.w[i].clone().into();

        // \beta * s
        let tmp = cs.mul(beta, si);

        // + w[i]
        let tmp = cs.add(tmp, wi);

        // + \gamma
        cs.add(tmp, gamma)
    }));

    var_product(cs, prod.into_iter())
}

/// Compute the permutation argument part of the
fn compute_ft_perm<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    index: &ConstIndex<F>,
    zh_zeta: &polynomials::VanishEval<F>,
    eval: &VarEvaluations<F>,
    gamma: Var<F>,
    beta: Var<F>,
    zeta: Var<F>,
    alpha: &[Var<F>; 3],
) -> Var<F> {
    // evaluate the (constant) ZKP polynomial at \zeta, i.e. zkpm(\zeta)
    let zkp = eval_const_poly(cs, &index.zkpm, zeta);

    // shuffle proof related constraints
    let term_recurrence = {
        // $\prod_i \left((\beta s_i) + w_i + \gamma\right)$
        let before: Var<_> = {
            let mut prod = (0..PERMUTS - 1)
                .map(|i| {
                    let si = eval.zeta.s[i].clone().into();
                    let wi = eval.zeta.w[i].clone().into();

                    // \beta * s
                    let tmp = cs.mul(beta, si);

                    // + w[i]
                    let tmp = cs.add(tmp, wi);

                    // + \gamma
                    cs.add(tmp, gamma)
                })
                .collect::<Vec<Var<_>>>();

            // last column is handled differently:
            // linearlization optimization
            prod.push(cs.add(eval.zeta.w[PERMUTS - 1].clone().into(), gamma));

            // * z(\zeta\omega)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zetaw.z.clone().into());
            var_product(cs, prod.into_iter())
        };

        // $\prod_i left((\zeta  \beta shift_i) + w_i + \gamma\right)$
        let after: Var<_> = {
            let mut prod = (0..PERMUTS)
                .map(|i| {
                    let ki = index.shift[i];
                    let wi = eval.zeta.w[i].clone().into();

                    // beta * zeta * shift;
                    let tmp = generic!(cs, (beta, zeta) : { ? = beta * ki * zeta });

                    // + w[i]
                    let tmp = cs.add(tmp, wi);

                    // + \gamma
                    cs.add(tmp, gamma)
                })
                .collect::<Vec<Var<_>>>();

            // * z(\zeta)
            debug_assert_eq!(prod.len(), PERMUTS);
            prod.push(eval.zeta.z.clone().into());
            var_product(cs, prod.into_iter())
        };

        // (<before> - <after>)
        let diff = cs.sub(before, after);

        // * zkp(\zeta)
        let mask = cs.mul(diff, zkp);
        cs.mul(mask, alpha[0])
    };

    // boundary condition on permutation proof
    // this is somewhat more complicated that in the original kimchi due to the zkp polynomial
    let term_boundary = {
        let one: F = F::one();
        let omega: F = index.domain.group_gen;

        let zhz: Var<F> = zh_zeta.as_ref().clone();
        let eval0_z: Var<F> = eval.zeta.z.clone().into();

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

    cs.add(term_boundary, term_recurrence)
}

/// Combine multiple openings using a linear combination
///
/// QUESTION: why can this not just be one large linear combination,
/// why do we need both xi and r?
fn combine_inner_product<'a, F, C: Cs<F>, const N: usize>(
    cs: &mut C,
    evaluations: &[(Var<F>, Vec<VarEval<F, N>>)], // evaluation point and openings
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

// TODO: add unit test for compat with combined_inner_product from Kimchi using Witness Generator

// public input is a polynomial in Lagrange basis
// (where accessing an evaluation of the poly requires absorption)
pub struct PublicInput<G>(LagrangePoly<G::ScalarField>)
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField;

impl<G> PublicInput<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub fn eval<C: Cs<G::ScalarField>>(
        &self,
        cs: &mut C,
        x: Var<G::ScalarField>,
        pnt: &polynomials::VanishEval<G::ScalarField>,
    ) -> Msg<VarEval<G::ScalarField, 1>> {
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
    /// Takes a mutual context with the base-field of the Plonk proof as the "native field"
    /// and generates Fp (base field) and Fr (scalar field)
    /// constraints for the verification of the proof.
    ///
    /// The goal is for this method to look as much as the "clear verifier" in Kimchi.
    ///
    pub fn verify<CsFp, CsFr, C, T>(
        self,
        // ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
        ctx: &mut Context<G::BaseField, G::ScalarField, CsFp, CsFr>,
        p_comm: Msg<VarPolyComm<G, 1>>,
        inputs: &PublicInput<G>, // commitment to public input
        proof: VarProof<G, 2>,
    ) where
        CsFp: Cs<G::BaseField>,
        CsFr: Cs<G::ScalarField>,
    {
        // sanity checks
        assert_eq!(inputs.len(), self.constant.public_input_size);

        // start a new transcript
        let mut tx = Arthur::new(ctx);

        //~ 1. absorb index
        // absorb variable part of the index: the relation description
        let relation = tx.recv(ctx, self.relation);

        //~ 1. absorb accumulator commitments
        let acc_comms = tx.recv(ctx, proof.prev_challenges.comm);

        //~ 2. Absorb commitment to the public input polynomial
        let p_comm = tx.recv(ctx, p_comm);

        //~ 3. Absorb commitments to the registers / witness columns
        let w_comm = tx.recv(ctx, proof.commitments.w_comm);

        //~ 6. Sample $\beta$
        let beta: FieldChallenge<_> = tx.challenge(ctx); // sample challenge using Fp sponge
        let beta: FieldChallenge<_> = ctx.pass(&beta); // pass to other side
        let beta: Var<G::ScalarField> = beta.into(); // interpret as variable

        //~ 7. Sample $\gamma$
        let gamma: FieldChallenge<_> = tx.challenge(ctx); // sample challenge using Fp sponge
        let gamma: FieldChallenge<_> = ctx.pass(&gamma); // pass to other side
        let gamma: Var<G::ScalarField> = gamma.into(); // interpret as variable

        //~ 8. If using lookup, absorb the commitment to the aggregation lookup polynomial.
        /*self.commitments.lookup.iter().for_each(|l| {
            fq_sponge.absorb_g(&l.aggreg.unshifted);
        });
        */

        //~ 9. Absorb the commitment to the permutation trace with the Fq-Sponge.
        let z_comm = tx.recv(ctx, proof.commitments.z_comm);

        //~ 10. Sample $\alpha'$ (GLV decomposed scalar)
        let alpha_glv: GLVChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism
        let alpha: GLVChallenge<G::ScalarField> = ctx.pass(&alpha_glv);
        let alpha: Var<G::ScalarField> = ctx.flip(|ctx| alpha.to_field(ctx.cs()));

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        // CHANGE: Happens at deserialization time (it is an array).

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        let t_comm = tx.recv(ctx, proof.commitments.t_comm);

        //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$)
        let zeta_glv: GLVChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta: GLVChallenge<G::ScalarField> = ctx.pass(&zeta_glv);
        let zeta: Var<G::ScalarField> = ctx.flip(|ctx| zeta.to_field(ctx.cs()));

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        //~     Absorb over the foreign field

        // Enforce constraints on other side
        let (_, scalars, commitments, shift_zeta) = ctx.flip(|ctx| {
            tx.flip(|tx| {
                let alphas: Alphas<_> = Alphas::new(ctx.cs(), alpha);

                // zetaw = zeta * \omega
                let omega = self.constant.domain.group_gen;
                let zetaw = generic!({ ctx.cs() }, (zeta) : { ? = omega * zeta } );

                // compute shift polynomial: $\zeta^{|domain size|}$
                let shift_zeta = polynomials::ShiftEval::new(ctx.cs(), &self.constant.domain, zeta);

                // compute vanishing polynomial (of domain) at $\zeta$
                // note that $Z_H(\zeta) = Z_H(\zeta \omega)$: we only need to eval one
                let vanish_zeta = polynomials::VanishEval::new(ctx.cs(), &shift_zeta);

                //~ 19. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
                //~     - the public polynomial
                //~     - z
                //~     - generic selector
                //~     - poseidon selector
                //~     - the 15 register/witness
                //~     - 6 sigmas evaluations (the last one is not evaluated)

                // absorb $\zeta$ evaluations
                let p_zeta = inputs.eval(ctx.cs(), zeta, &vanish_zeta);
                let p_zeta = tx.recv(ctx, p_zeta);
                let e_zeta = tx.recv(ctx, proof.evals.zeta);

                // absorb $\zeta\omega$ evaluations
                let p_zetaw = inputs.eval(ctx.cs(), zetaw, &vanish_zeta);
                let p_zetaw = tx.recv(ctx, p_zetaw);
                let e_zetaw = tx.recv(ctx, proof.evals.zetaw);

                // setup Expr evaluator with evaluations provided by prover
                let evals = VarEvaluations {
                    zeta: e_zeta,
                    zetaw: e_zetaw,
                };

                let mut evalutator = Evaluator::new(
                    zeta,
                    self.constant.domain.clone(),
                    Assignments {
                        alpha,
                        beta,
                        gamma,
                        constants: self.constant.constants.clone(),
                    },
                    &evals,
                );

                // compute ft_eval0
                let ft_zeta = {
                    let term_perm = compute_ft_perm(
                        ctx.cs(),
                        &self.constant,
                        &vanish_zeta,
                        &evals,
                        gamma,
                        beta,
                        zeta,
                        alphas.permutation().try_into().unwrap(),
                    );

                    let term_row = {
                        // evaluate constant term of the row constraint linearization
                        let row_poly = evalutator
                            .eval_expr(ctx.cs(), &self.constant.linearization.constant_term);

                        // subtract $p(\zeta)$ and negate
                        ctx.add(row_poly, p_zeta.clone().into())
                    };

                    ctx.sub(term_perm, term_row).into()
                };

                //~ 20. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
                let ft_zetaw = tx.recv(ctx, proof.ft_eval1);

                // receive accumulator challenges (IPA challenges)
                let acc_chals = tx.recv(ctx, proof.prev_challenges.chal);

                //~ 21. Sample $v'$ with the Fr-Sponge.
                let v_chal: GLVChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                let v: Var<G::ScalarField> = v_chal.to_field(ctx.cs());

                //~ 23. Sample $u'$ with the Fr-Sponge.
                let u_chal: GLVChallenge<G::ScalarField> = tx.challenge(ctx);

                //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                let u = u_chal.to_field(ctx.cs());

                // evaluate the $h(X)$ polynomials from the accumulators at $\zeta$
                let h_zeta: Vec<VarEval<_, 1>> = acc_chals
                    .iter()
                    .map(|acc| acc.eval_h(ctx.cs(), zeta))
                    .collect();

                // evaluate the $h(X)$ polynomials from the accumulators at $\zeta\omega$
                let h_zetaw: Vec<VarEval<_, 1>> = acc_chals
                    .iter()
                    .map(|acc| acc.eval_h(ctx.cs(), zetaw))
                    .collect();

                //~ 25. Create a list of all polynomials that have an evaluation proof.
                // evaluations at $\zeta$
                let evals_z = iter::empty()
                    .chain(h_zeta) // $h(\zeta)$
                    .chain(iter::once(p_zeta)) // p_eval(\zeta)
                    .chain(iter::once(ft_zeta)) // ft_eval0
                    .chain(evals.zeta.iter().cloned()); // openings from proof

                // evaluations at $\zeta \omega$
                let evals_zw = iter::empty()
                    .chain(h_zetaw) // $h(\zeta\omega)$
                    .chain(iter::once(p_zetaw)) // p_eval(\zeta\omega)
                    .chain(iter::once(ft_zetaw)) // ft_eval1
                    .chain(evals.zetaw.iter().cloned()); // openings from proof

                // evaluate every linearlization term and
                // associate with corresponding polynomial commitment
                let mut scalars: Vec<Var<G::ScalarField>> = Vec::new();
                let mut commitments: Vec<&VarPolyComm<G, 1>> = Vec::new();
                for (col, expr) in &self.constant.linearization.index_terms {
                    let scalar = evalutator.eval_expr(ctx.cs(), expr);

                    use Column::*;
                    match col {
                        Witness(i) => {
                            scalars.push(scalar);
                            commitments.push(&w_comm[*i])
                        }
                        Coefficient(i) => {
                            scalars.push(scalar);
                            commitments.push(&relation.coefficients_comm[*i])
                        }
                        Z => {
                            scalars.push(scalar);
                            commitments.push(&z_comm);
                        }
                        Index(t) => {
                            use GateType::*;
                            let c = match t {
                                Zero | Generic | Lookup => {
                                    panic!("Selector for {:?} not defined", t)
                                }
                                CompleteAdd => &relation.complete_add_comm,
                                VarBaseMul => &relation.mul_comm,
                                EndoMul => &relation.emul_comm,
                                EndoMulScalar => &relation.endomul_scalar_comm,
                                Poseidon => &relation.psm_comm,
                                ChaCha0 => &relation.chacha_comm.as_ref().unwrap()[0],
                                ChaCha1 => &relation.chacha_comm.as_ref().unwrap()[1],
                                ChaCha2 => &relation.chacha_comm.as_ref().unwrap()[2],
                                ChaChaFinal => &relation.chacha_comm.as_ref().unwrap()[3],
                                CairoClaim | CairoInstruction | CairoFlags | CairoTransition => {
                                    unimplemented!()
                                }
                                RangeCheck0 => &relation.range_check_comm[0],
                                RangeCheck1 => &relation.range_check_comm[1],
                            };
                            scalars.push(scalar);
                            commitments.push(c);
                        }
                        _ => unimplemented!(), // TODO: lookup related column types
                    }
                }

                // pass scalars to G::BaseField side for ft_comm computation (MSM inside circuit)
                let scalars: Vec<Scalar<G>> = scalars.into_iter().map(|s| ctx.pass(&s)).collect();

                // compute the combined inner product:
                // the batching of all the openings
                let combined_inner_product = {
                    // compute a randomized combinations of all the openings
                    // with xi = v, r = u
                    combine_inner_product(
                        ctx.cs(),
                        &vec![
                            (zeta, evals_z.collect()),   // (eval point, openings)
                            (zetaw, evals_zw.collect()), // (eval point, openings)
                        ],
                        v, // xi
                        u, // r
                    )
                };

                let shift_zeta: Scalar<G> = ctx.pass(shift_zeta.as_ref());

                (combined_inner_product, scalars, commitments, shift_zeta)
            })
        });

        // compute ft_comm MSM (linearlizated row constraints based on gate selectors)
        let f_comm: VarPolyComm<G, 1> =
            VarPolyComm::linear_combination(ctx.cs(), scalars.iter().zip(commitments));

        // compute the chunked commitment of ft: 
        // the prover provides the negated qoutient (t), the linearlization is the remainder: i.e.
        //
        // $$
        // ft(X) = f(X) - t(X) \cdot Z_H(X)
        // $$
        let ft_comm: VarPolyComm<G, 1> = {
            let t_collapsed: VarPolyComm<G, 1> = t_comm.collapse(ctx.cs(), &shift_zeta);
            let t_collapsed: VarPolyComm<G, 1> = t_collapsed.mul_vanish(ctx.cs(), &shift_zeta);
            f_comm.sub(ctx.cs(), &t_collapsed) // f_comm is already a single chunk, hence collapse is a no-op
        };

        // compute combined polynomial opening
        let poly_comms = iter::empty()
            .chain(&acc_comms) // * [\alpha^0]
            .chain(iter::once(&p_comm)) // * [\alpha^1]
            .chain(iter::once(&ft_comm)) // * [\alpha^2]
            .chain(iter::once(&z_comm)) // ...
            .chain(iter::once(&relation.generic_comm))
            .chain(iter::once(&relation.psm_comm))
            .chain(&w_comm)
            .chain(&relation.sigma_comm);

        // combine all $\zeta$ openings using powers of $\alpha$
        let combined_comm = VarPolyComm::combine_with_glv(ctx.cs(), poly_comms, &alpha_glv);

        // TODO: add the lookup terms
    }
}
