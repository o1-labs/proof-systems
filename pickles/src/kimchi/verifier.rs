use std::iter;

use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::{generic, Cs, Var};

use kimchi::circuits::expr::Column;
use kimchi::circuits::gate::GateType;
use kimchi::circuits::wires::{COLUMNS, PERMUTS};

use crate::kimchi::alphas::Alphas;
use crate::kimchi::batch::combine_inner_product;
use crate::kimchi::constraints;
use crate::kimchi::index::{ConstIndex, Index};
use crate::kimchi::proof::{PublicInput, VarEvaluations, VarProof};

use crate::context::Context;
use crate::expr::{Assignments, Evaluator};
use crate::transcript::{Arthur, Msg};
use crate::types::{polynomials, FieldChallenge, GLVChallenge, Scalar, VarEval, VarPolyComm};
use crate::util::var_product;

/// Compute the permutation argument part of the
fn compute_ft_perm<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    index: &ConstIndex<F>,
    zh_zeta: &polynomials::VanishEval<F>,
    zkp_zeta: &polynomials::ZKPEval<F>,
    eval: &VarEvaluations<F>,
    gamma: Var<F>,
    beta: Var<F>,
    zeta: Var<F>,
    alpha: &[Var<F>; 3],
) -> Var<F> {
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
        let mask = cs.mul(diff, *zkp_zeta.as_ref());
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

// TODO: add unit test for compat with combined_inner_product from Kimchi using Witness Generator

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
        let mut tx = Arthur::new(ctx.constants());

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
        let beta: FieldChallenge<_> = ctx.pass(beta); // pass to other side
        let beta: Var<G::ScalarField> = beta.into(); // interpret as variable

        //~ 7. Sample $\gamma$
        let gamma: FieldChallenge<_> = tx.challenge(ctx); // sample challenge using Fp sponge
        let gamma: FieldChallenge<_> = ctx.pass(gamma); // pass to other side
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
        let alpha: GLVChallenge<G::ScalarField> = ctx.pass(alpha_glv);
        let alpha: Var<G::ScalarField> = ctx.flip(|ctx| alpha.to_field(ctx.cs()));

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        // CHANGE: Happens at deserialization time (it is an array).

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        let t_comm = tx.recv(ctx, proof.commitments.t_comm);

        //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$)
        let zeta_glv: GLVChallenge<G::BaseField> = tx.challenge(ctx);

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta: GLVChallenge<G::ScalarField> = ctx.pass(zeta_glv);
        let zeta: Var<G::ScalarField> = ctx.flip(|ctx| zeta.to_field(ctx.cs()));

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        //~     Absorb over the foreign field

        // pass transcript to other side
        let mut tx: Arthur<G::ScalarField> = ctx.pass(tx);

        // enforce constraints on other side
        let (evals_z, evals_zw, scalars, commitments, shift_zeta) = ctx.flip(|ctx| {
            let alphas: Alphas<_> = Alphas::new(ctx.cs(), alpha);

            // zetaw = zeta * \omega
            let omega = self.constant.domain.group_gen;
            let zetaw = generic!({ ctx.cs() }, (zeta) : { ? = omega * zeta } );

            // compute shift polynomial: $\zeta^{|domain size|}$
            let shift_zeta = polynomials::ShiftEval::new(ctx.cs(), &self.constant.domain, zeta);

            // compute vanishing polynomial (of domain) at $\zeta$
            // note that $Z_H(\zeta) = Z_H(\zeta \omega)$: we only need to eval one
            let vanish_zeta = polynomials::VanishEval::new(ctx.cs(), &shift_zeta);

            // evaluate the ZKP (masking polynomial)
            let zkp_zeta = polynomials::ZKPEval::new(ctx.cs(), &self.constant, zeta);

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
                    &zkp_zeta,
                    &evals,
                    gamma,
                    beta,
                    zeta,
                    alphas.permutation().try_into().unwrap(),
                );

                let term_row = {
                    // evaluate constant term of the row constraint linearization
                    let row_poly =
                        evalutator.eval_expr(ctx.cs(), &self.constant.linearization.constant_term);

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
            let evals_z: Vec<_> = iter::empty()
                .chain(h_zeta) // $h(\zeta)$
                .chain(iter::once(p_zeta)) // p_eval(\zeta)
                .chain(iter::once(ft_zeta)) // ft_eval0
                .chain(evals.zeta.iter().cloned())
                .collect(); // openings from proof

            // evaluations at $\zeta \omega$
            let evals_zw: Vec<_> = iter::empty()
                .chain(h_zetaw) // $h(\zeta\omega)$
                .chain(iter::once(p_zetaw)) // p_eval(\zeta\omega)
                .chain(iter::once(ft_zetaw)) // ft_eval1
                .chain(evals.zetaw.iter().cloned())
                .collect();

            // evaluate every linearlization term and
            // associate with corresponding polynomial commitment
            let mut scalars: Vec<Var<G::ScalarField>> = Vec::new();
            let mut commitments: Vec<&VarPolyComm<G, 1>> = Vec::new();

            // handle permutation argument
            {
                let perm_scalar = constraints::perm_scalar(
                    ctx.cs(),
                    &evals,
                    beta,
                    gamma,
                    alphas.permutation(),
                    &zkp_zeta,
                );
                scalars.push(perm_scalar);
                commitments.push(&relation.sigma_comm[PERMUTS - 1])
            }

            // handle generic gate
            {
                let generic_scalars = constraints::generic_scalars(ctx.cs(), alphas.gate(), &evals);
                let generic_comm = relation
                    .coefficients_comm
                    .iter()
                    .take(generic_scalars.len());
                scalars.extend(generic_scalars);
                commitments.extend(generic_comm);
            }

            // handle all other types of gates
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
            // TODO: this can be avoid by not using linearlization in the future
            let scalars: Vec<Scalar<G>> = scalars.into_iter().map(|s| ctx.pass(s)).collect();

            // we also need to pass $\zeta^{|H|}$ to the other side
            let shift_zeta: Scalar<G> = ctx.pass(shift_zeta.as_ref().clone());

            //
            let v_chal = ctx.pass(v_chal);

            (evals_z, evals_zw, scalars, commitments, shift_zeta)
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
            // collapse at  $\zeta$
            let t_collapsed: VarPolyComm<G, 1> = t_comm.collapse(ctx.cs(), &shift_zeta);

            // multiply by $Z_H(X)$
            let t_collapsed: VarPolyComm<G, 2> = t_collapsed.mul_vanish(ctx.cs());

            // collapse at $\zeta$ again
            let t_collapsed: VarPolyComm<G, 1> = t_collapsed.collapse(ctx.cs(), &shift_zeta);

            f_comm.sub(ctx.cs(), &t_collapsed) // f_comm is already a single chunk, hence collapse is a no-op
        };

        // compute combined polynomial opening
        let comms: Vec<_> = iter::empty()
            .chain(&acc_comms) // * [\alpha^0]
            .chain(iter::once(&p_comm)) // * [\alpha^1]
            .chain(iter::once(&ft_comm)) // * [\alpha^2]
            .chain(iter::once(&z_comm)) // ...
            .chain(iter::once(&relation.generic_comm))
            .chain(iter::once(&relation.psm_comm))
            .chain(&w_comm)
            .chain(&relation.sigma_comm)
            .collect();

        // sanity check: the number of commitments is the same as the number of evaluations
        assert_eq!(comms.len(), evals_z.len());
        assert_eq!(comms.len(), evals_zw.len());

        // combine/aggregate openings

        // combine openings using random challenge
        // DISCUSS: v (xi) is NEVER USED in kimchi: the power is always 0..., since there is always one chunk!
        // The evaluation points are also never used since the shift is always None.
        // hence "combined_inner_product" simplifies to this.
        //
        // Why does this work when the evaluations are at different points: \zeta, \zeta\omega ?
        /*
        let combined_opening: VarEval<_, 1> = VarEval::combine(
            ctx.cs(),
            evals_z.chain(evals_zw).collect::<Vec<_>>().iter(),
            v
        );

        // combine all $\zeta$ openings using powers of $\alpha$
        let combined_comm = VarPolyComm::combine_with_glv(ctx.cs(), poly_comms, &alpha_glv);
        */
    }
}
