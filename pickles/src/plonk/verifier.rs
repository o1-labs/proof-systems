use super::{Proof};

use circuit_construction::{Constants, Cs, Var};

use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use crate::context::{Context};
use crate::transcript::{Arthur, Msg};
use crate::plonk::proof::{VarProof, ScalarChallenge, VarPolyComm, VarIndex};

impl <A> VarIndex<A> where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField {

    /// Takes a mutual context with the base-field of the Plonk proof as the "native field"
    /// and generates Fp (base field) and Fr (scalar field)
    /// constraints for the verification of the proof.
    ///
    ///
    fn verify<CsFp, CsFr, C, T>(
        &self,
        // ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
        ctx: &mut Context<A::BaseField, A::ScalarField, CsFp, CsFr>,
        p_comm: Msg<VarPolyComm<A, 1>>,  // commitment to public input
        witness: Option<Proof<A>>, // witness (a PlonK proof)
    ) where
        CsFp: Cs<A::BaseField>,
        CsFr: Cs<A::ScalarField>,
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
        let beta: Var<A::BaseField> = tx.challenge(ctx);

        //~ 7. Sample $\gamma$
        let gamma: Var<A::BaseField> = tx.challenge(ctx);

        //~ 10. Sample $\alpha'$
        let alpha_chal: ScalarChallenge<A::BaseField> = tx.challenge(ctx);

        //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
        let alpha: Var<A::BaseField> = alpha_chal.to_field(ctx);
        let alpha = ctx.pass(alpha);

        //~ 12. Enforce that the length of the $t$ commitment is of size `PERMUTS`.
        // CHANGE: Happens at deserialization time (it is an array).

        //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
        let t_comm = tx.recv(ctx, proof.commitments.t_comm);

        //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$)
        let zeta_chal: ScalarChallenge<A::BaseField> = tx.challenge(ctx);

        //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
        let zeta: Var<A::BaseField> = zeta_chal.to_field(ctx);
        let zeta = ctx.pass(zeta);

        //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
        //~     Absorb over the foreign field

        // On the other side
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
                let v_chal: ScalarChallenge<A::ScalarField> = tx.challenge(ctx);

                //~ 22. Derive $v$ from $v'$ using the endomorphism (TODO: specify).
                let v: Var<A::ScalarField> = v_chal.to_field(ctx);

                //~ 23. Sample $u'$ with the Fr-Sponge.
                let u_chal: ScalarChallenge<A::ScalarField> = tx.challenge(ctx);

                //~ 24. Derive $u$ from $u'$ using the endomorphism (TODO: specify).
                let u = u_chal.to_field(ctx);

                //~ 25. Create a list of all polynomials that have an evaluation proof.

                (evals, ft_eval, v_chal, v)
            })
        });

        // ctx can be used as a Cs<Fp>
        ctx.var(|| unimplemented!());
        ctx.fp.cs.var(|| unimplemented!());
    }
}

