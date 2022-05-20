use crate::context::MutualContext;
use crate::transcript::{Merlin, Passable, Challenge, Absorb, Msg, ZkSponge};
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
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut ZkSponge<A::BaseField>) {
        sponge.absorb(cs, &self.x);
        sponge.absorb(cs, &self.y);
    }
}

struct VarCommitments<A>
    where
A: AffineCurve,
A::BaseField: FftField + PrimeField {
    w_comm: Msg<[VarPoint<A>; COLUMNS]>,
    t_comm: Msg<VarPoint<A>>,
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

// TODO: I would really like to derieve this, 
// but it means settling on an order which is the same as in the struct!
impl <F: FftField + PrimeField> Absorb<F> for VarEvaluation<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut ZkSponge<F>) {
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

struct VarProof<A> 
    where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    commitments: VarCommitments<A>,
    ft_eval1: Msg<Var<A::ScalarField>>,
    p_eval: Msg<[Var<A::ScalarField>; 6]>,

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
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut ZkSponge<F>) -> Self {
        // generate challenge using sponge
        let scalar: Var<F> = Var::generate(cs, sponge);

        // create endoscalar (bit decompose)
        // QUESTION: what does the length refer to here?
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

impl <F: FftField + PrimeField> ScalarChallenge<F> {
    fn to_field(&self, constants: &Constants<F>) -> Var<F> {
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
    tx: &mut Merlin<A::BaseField, A::ScalarField, CsFp, CsFr>,
    index: VarIndex<A>,        // verifier index
    p_comm: Msg<VarPoint<A>>,  // commitment to public input
    witness: Option<Proof<A>>, // witness (a PlonK proof)
) where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
    CsFp: Cs<A::BaseField>,
    CsFr: Cs<A::ScalarField>,
{
    // create proof instance (with/without witness)
    let pf = VarProof::new(witness);

    //~ 2. Absorb the commitment of the public input polynomial with the Fq-Sponge.
    let p_comm = tx.recv(p_comm);

    //~ 3. Absorb the commitments to the registers / witness columns with the Fq-Sponge.
    let w_comm = tx.recv(pf.commitments.w_comm);

    //~ 6. Sample $\beta$ with the Fq-Sponge.
    let beta: Var<A::BaseField> = tx.challenge();

    //~ 7. Sample $\gamma$ with the Fq-Sponge.
    let gamma: Var<A::BaseField> = tx.challenge();

    //~ 10. Sample $\alpha'$ with the Fq-Sponge.
    let alpha_chal: ScalarChallenge<A::BaseField> = tx.challenge();

    //~ 11. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details).
    let alpha: Var<A::ScalarField> = tx.pass_fits( // pass to other side
        alpha_chal.to_field(tx.constants()),
    );

    //~ 13. Absorb the commitment to the quotient polynomial $t$ into the argument.
    let t_comm = tx.recv(pf.commitments.t_comm);

    //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$) with the Fq-Sponge.
    let zeta_chal: ScalarChallenge<A::BaseField> = tx.challenge();

    //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
    let zeta: Var<A::ScalarField> = tx.pass_fits( // pass to other side
        zeta_chal.to_field(tx.constants()),
    );

    

   

    let ft_eval = tx.recv_fr(pf.ft_eval1);
    let p_eval = tx.recv_fr(pf.p_eval);
}
