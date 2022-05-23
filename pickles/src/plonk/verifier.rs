use crate::context::{Context, Passable};
use crate::transcript::{Merlin, Challenge, Absorb, Msg, VarSponge};
use std::iter;

use super::{Proof, COLUMNS, PERMUTS, CHALLENGE_LEN, SELECTORS};

use circuit_construction::{Cs, Constants, Var};

use ark_ec::AffineCurve;
use ark_ff::{FftField, FpParameters, PrimeField};

use std::marker::PhantomData;

struct VarIndex<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    q: [VarPoint<A>; SELECTORS], // commits to selector polynomials
}

struct VarPoint<A>
where 
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    x: Var<A::BaseField>,
    y: Var<A::BaseField>
}

impl <A> Absorb<A::BaseField> for VarPoint<A>
where 
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{ 
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.x);
        sponge.absorb(cs, &self.y);
    }
}

struct VarCommitments<A>
    where
A: AffineCurve,
A::BaseField: FftField + PrimeField {
    w_comm: Msg<[VarPoint<A>; COLUMNS]>,
    t_comm: Msg<[VarPoint<A>; PERMUTS]>,
    z_comm: Msg<VarPoint<A>>
}

struct VarEvaluation<F: FftField + PrimeField> {
    /// witness polynomials
    pub w: [Var<F>; COLUMNS],
    
    /// permutation polynomial
    pub z: Var<F>,

    /// permutation polynomials
    /// (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
    pub s: [Var<F>; PERMUTS - 1],

    /// lookup-related evaluations
    //pub lookup: Option<LookupEvaluations<Field>>,

    /// evaluation of the generic selector polynomial
    pub generic_selector: Var<F>,

    /// evaluation of the poseidon selector polynomial
    pub poseidon_selector: Var<F>,
}

// DISCUSS: I would really like to #[derieve(Absorb)] this, 
// but it means settling on an order which is the same as in the struct!
impl <F: FftField + PrimeField> Absorb<F> for VarEvaluation<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        // concatenate
        let points = iter::empty()
            .chain(iter::once(&self.z))
            .chain(iter::once(&self.generic_selector))
            .chain(iter::once( &self.poseidon_selector))
            .chain(self.w.iter())
            .chain(self.s.iter());

        // absorb in order
        points.for_each(|p| sponge.absorb(cs, p));
    }
}

struct VarEvaluations<F: FftField + PrimeField> {
    z: VarEvaluation<F>,  // evaluation at z
    zw: VarEvaluation<F>, // evaluation at z * \omega (2^k root of unity, next step)
}


impl <F: FftField + PrimeField> Absorb<F> for VarEvaluations<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.z);
        sponge.absorb(cs, &self.zw);
    }
}

///
/// 
/// WARNING: Make sure this only contains Msg types 
/// (or structs of Msg types)
struct VarProof<A> 
    where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    commitments: VarCommitments<A>,
    ft_eval1: Msg<Var<A::ScalarField>>,
    evals: Msg<VarEvaluations<A::ScalarField>>,
}

impl <A> VarProof<A> 
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField
    {

    
    fn new(witness: Option<Proof<A>>) -> Self {
        unimplemented!()
    }
}

struct ScalarChallenge<F: FftField + PrimeField> {
    challenge: Var<F>,
}

impl<F: FftField + PrimeField> Passable<F> for ScalarChallenge<F> {
    const SIZE: usize = CHALLENGE_LEN;
}

impl<F: FftField + PrimeField> Passable<F> for Var<F> {
    const SIZE: usize = F::Params::MODULUS_BITS as usize;
}

impl<F: FftField + PrimeField> Into<Var<F>> for ScalarChallenge<F> {
    fn into(self) -> Var<F> {
        self.challenge
    }
}

impl<F: FftField + PrimeField> Challenge<F> for ScalarChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        // generate challenge using sponge
        let scalar: Var<F> = Var::generate(cs, sponge);

        // create endoscalar (bit decompose)
        let challenge = cs.endo_scalar(CHALLENGE_LEN, || {
            let s: F = scalar.val();
            s.into_repr()
        });

        // enforce equality
        cs.assert_eq(challenge, scalar);

        // bit decompose challenge
        ScalarChallenge{ challenge }
    }
}

impl <Fp: FftField + PrimeField> ScalarChallenge<Fp> {
    fn to_field<Fr, CsFp, CsFr>(&self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> Var<Fp> where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>, 
        CsFr: Cs<Fr> {
        unimplemented!()
    }  
}

/// Takes a mutual context with the base-field of the Plonk proof as the "native field"
/// and generates Fp (base field) and Fr (scalar field)
/// constraints for the verification of the proof.
/// 
/// 
fn verify<A, CsFp, CsFr, C, T>(
    // ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
    ctx: &mut Context<A::BaseField, A::ScalarField, CsFp, CsFr>,
    index: VarIndex<A>,        // verifier index
    p_comm: Msg<VarPoint<A>>,  // commitment to public input
    witness: Option<Proof<A>>, // witness (a PlonK proof)
) where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
    CsFp: Cs<A::BaseField>,
    CsFr: Cs<A::ScalarField>,
{
    // start new transcript
    let mut tx = Merlin::new(ctx);

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

    //~ 16. Setup the Fr-Sponge.
    // CHANGE: Automatic
        
    //~ 17. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
    // CHANGE: Automatic

    //~ 18. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
    //~     NOTE: this works only in the case when the poly segment size is not smaller than that of the domain.
    //~     Absorb over the foreign field
    let evals = tx.recv_fr(ctx, proof.evals);

    let ft_eval = tx.recv_fr(ctx, proof.ft_eval1);
    //let p_eval = tx.recv_fr(pf.p_eval);

    // ctx can be used as a Cs<Fp>
    ctx.var(|| {unimplemented!() });
}
