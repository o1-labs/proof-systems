use crate::context::MutualContext;
use crate::transcript::{Merlin, Passable, Challenge, Absorb, Msg, ZkSponge};

use super::{Proof, COLUMNS, CHALLENGE_LEN, SELECTORS};

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

struct VarProof<A> 
    where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<A>,
    commitments: Msg<[VarPoint<A>; COLUMNS]>,
    ft_eval1: Msg<Var<A::ScalarField>>,
    p_eval: Msg<[Var<A::ScalarField>; 6]>
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
    index: VarIndex<A>,
    p_comm: Msg<VarPoint<A>>,
    witness: Option<Proof<A>>,
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
    let commitments = tx.recv(pf.commitments);

    //~ 6. Sample $\beta$ with the Fq-Sponge.
    let beta: Var<A::BaseField> = tx.challenge();

    //~ 7. Sample $\gamma$ with the Fq-Sponge.
    let gamma: Var<A::BaseField> = tx.challenge();

    //~ 14. Sample $\zeta'$ (GLV decomposition of $\zeta$) with the Fq-Sponge.
    let zeta_chal: ScalarChallenge<A::BaseField> = tx.challenge();

    //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
    let zeta: Var<A::ScalarField> = tx.pass_fits( // pass though
        zeta_chal.to_field(tx.constants()),
    );

    //~ 8. If using lookup, absorb the commitment to the aggregation lookup polynomial.
    // Question: why is done after (beta/gamma) challenge?
    /*
    self.commitments.lookup.iter().for_each(|l| {
        fq_sponge.absorb_g(&l.aggreg.unshifted);
    });
    */

    let ft_eval = tx.recv_fr(pf.ft_eval1);
    let p_eval = tx.recv_fr(pf.p_eval);
}
