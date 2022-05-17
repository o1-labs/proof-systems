use crate::context::MutualContext;
use crate::transcript::{Merlin, Challenge, Absorb, Msg, ZkSponge};

use super::{Proof, COLUMNS, CHALLENGE_LEN, SELECTORS};

use circuit_construction::{Cs, Var};

use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

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
    chal: Var<F>,
}

impl<F: FftField + PrimeField> Challenge<F> for ScalarChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut ZkSponge<F>) -> Self {
        // QUESTION: how do I enforce equality between endoscalar and truncated oracle output using the CS api?
        // generate challenge using sponge
        let s: Var<F> = Var::generate(cs, sponge);

        // bit decompose challenge
        ScalarChallenge{
            chal: cs.endo_scalar(CHALLENGE_LEN, || {
                let s: F = s.val();
                s.into_repr()
            })
        }
    }
}

///
/// Takes a mutual context with the base-field of the Plonk proof as the "native field"
/// and generates Fp (base field) and Fr (scalar field)
/// constraints for the verification of the proof.
/// 
/// Question: why are Oracle outputs included in the proof (in Kimchi?)
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

    //~ 14. Sample $\zeta'$ with the Fq-Sponge.
    let zeta_chal: ScalarChallenge<A::BaseField> = tx.challenge();

    //~ 15. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify).
    // let zeta = zeta_chal.to_field(&index.srs.endo_r);


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
