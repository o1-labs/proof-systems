use self::instance::{Instance, RelaxedInstance};
use super::poseidon::DuplexState;
use super::prelude::*;
use crate::{
    curve::KimchiCurve,
    loc,
    snarky::api::SnarkyCircuit,
    snarky::{cvar::FieldVar, runner::RunState},
};
use ark_ec::AffineCurve;
use ark_ff::{BigInteger, One, PrimeField};
use mina_curves::pasta::Fp;
use std::marker::PhantomData;
use std::ops::Add;

mod instance;

const CHALLENGE_BITS: usize = 127;

struct FoldingCircuit<C: KimchiCurve, const N: usize> {
    _field: PhantomData<C>,
    ///commitment sets an their sizes
    commitments: Vec<usize>,
    ///challenges sets an their sizes
    challenges: Vec<usize>,
}

///the value of the input an output of the function being folded
struct Argument<F, const N: usize>([F; N]);
type Point<F> = [F; 2];
type Hash<F> = FieldVar<F>;

///an element of the other curve's field, it could use 2 limbs
#[derive(Debug, Clone)]
pub struct ForeignElement<F>([F; 2]);
///a 127 bits challenge
#[derive(Debug, Clone)]
struct SmallChallenge<F: PrimeField>(FieldVar<F>);
#[derive(Debug, Clone)]
pub struct FullChallenge<F>(ForeignElement<F>);
pub struct Private<F, const N: usize> {
    ///first input
    z_0: Argument<F, N>,
    ///input for this step and output of the previous one
    z_i: Argument<F, N>,
    ///all instances accumulated so far
    u_acc: RelaxedInstance<F>,
    ///newest instance to be folded into the accumulated instance
    u_i: Instance<F>,
    ///2 commitments to error terms to be used when folding the error column
    t: [Point<F>; 2],
    i: F,
}

/// this should run the inner circuit and provide its output, in our case it may be simpler
/// to just run the circuit separatly and provide the variables pointing to the output
fn apply<F: PrimeField, const N: usize>(
    _z_i: Argument<FieldVar<F>, N>,
) -> Argument<FieldVar<F>, N> {
    ///TODO
    todo!()
}

type F<C> = <C as AffineCurve>::ScalarField;

fn challenge_linear_combination<F: PrimeField>(
    _full: FullChallenge<FieldVar<F>>,
    _small: SmallChallenge<F>,
    _combiner: &SmallChallenge<F>,
) -> FullChallenge<FieldVar<F>> {
    ///TODO
    todo!()
}

fn commitment_linear_combination<F: PrimeField>(
    _a: Point<FieldVar<F>>,
    _b: Point<FieldVar<F>>,
    _combiner: &SmallChallenge<F>,
) -> Point<FieldVar<F>> {
    ///TODO
    todo!()
}
fn ec_add<F: PrimeField>(_a: Point<FieldVar<F>>, _b: Point<FieldVar<F>>) -> Point<FieldVar<F>> {
    ///TODO
    todo!()
}
fn ec_scale<F: PrimeField>(
    _point: Point<FieldVar<F>>,
    _scalar: &SmallChallenge<F>,
) -> Point<FieldVar<F>> {
    ///TODO
    todo!()
}
///trims to 127 bits
fn trim<F: PrimeField>(
    sys: &mut RunState<F>,
    v: &FieldVar<F>,
    base: &FieldVar<F>,
) -> SnarkyResult<FieldVar<F>> {
    let (high, low): (FieldVar<F>, FieldVar<F>) = sys.compute(loc!(), |wit| {
        let val = wit.read_var(v);
        let mut high = val.into_repr();
        high.divn(CHALLENGE_BITS as u32);
        let mut low = val.into_repr();
        low.sub_noborrow(&high);
        (F::from_repr(high).unwrap(), F::from_repr(low).unwrap())
    })?;
    let composition = high.mul(base, None, loc!(), sys)? + &low;
    ///TODO: constraint low to 127 bits
    v.assert_equals(sys, loc!(), &composition)?;
    Ok(low)
}

fn hash<F: PrimeField, const N: usize>(
    sys: &mut RunState<F>,
    i: FieldVar<F>,
    z_0: &Argument<FieldVar<F>, N>,
    z_i: &Argument<FieldVar<F>, N>,
    u: &RelaxedInstance<FieldVar<F>>,
    base: &FieldVar<F>,
) -> SnarkyResult<Hash<F>> {
    let mut sponge = DuplexState::new();

    sponge.absorb(sys, loc!(), &[i]);
    sponge.absorb(sys, loc!(), &z_0.0);
    sponge.absorb(sys, loc!(), &z_i.0);
    u.absorb_into_sponge(&mut sponge, sys);

    let hash = sponge.squeeze(sys, loc!());
    trim(sys, &hash, base)
}

impl<C: KimchiCurve, const N: usize> SnarkyCircuit for FoldingCircuit<C, N> {
    type Curve = C;

    type PrivateInput = Private<F<C>, N>;
    type PublicInput = ();
    type PublicOutput = [Hash<F<C>>; 2];

    fn circuit(
        &self,
        sys: &mut RunState<C::ScalarField>,
        _public: Self::PublicInput,
        private: Option<&Self::PrivateInput>,
    ) -> SnarkyResult<Self::PublicOutput> {
        let one = FieldVar::constant(F::<C>::one());
        //dividing by this should make a number of 127 bits or less zero
        let power = 1u128 << 127;
        let power = F::<C>::from(power);
        let power = FieldVar::Constant(power);

        let u_i: Instance<FieldVar<F<C>>> = Instance::compute(private, sys, &self.commitments)?;
        let hash1 = u_i.hash1.clone();
        let hash2 = u_i.hash2.clone();
        let u_acc: RelaxedInstance<FieldVar<F<C>>> =
            RelaxedInstance::compute(private, sys, &self.commitments, &self.challenges)?;

        //check hash of inputs
        let i: FieldVar<F<C>> = sys.compute(loc!(), |_| private.unwrap().i)?;
        let z_0: [FieldVar<F<C>>; N] = sys.compute(loc!(), |_| private.unwrap().z_0.0)?;
        let z_0 = Argument(z_0);
        let z_i: [FieldVar<F<C>>; N] = sys.compute(loc!(), |_| private.unwrap().z_i.0)?;
        let z_i = Argument(z_i);

        let inputs_hash = hash(sys, i.clone(), &z_0, &z_i, &u_acc, &power)?;

        inputs_hash.assert_equals(sys, loc!(), &hash1)?;

        let t = sys.compute(loc!(), |_| private.unwrap().t)?;
        let u_acc_new = u_acc.fold(sys, u_i, t, &power)?;
        let z_next = apply(z_i);
        let i = i.add(one);

        // here we should output this in some way so that it can be used as the input
        // for the next iteration, a Mutex or similar in &self could be used
        let new_hash = hash(sys, i, &z_0, &z_next, &u_acc_new, &power)?;

        Ok([hash2, new_hash])
    }
}

#[allow(dead_code)]
fn example<const N: usize>(private: Private<Fp, N>) {
    use mina_curves::pasta::VestaParameters;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

    let circuit = FoldingCircuit {
        _field: PhantomData,
        commitments: vec![15],
        challenges: vec![1, 5],
    };
    let (mut prover_index, verifier_index) = circuit.compile_to_indexes().unwrap();
    let (proof, public_output) = prover_index
        .prove::<BaseSponge, ScalarSponge>((), private, true)
        .unwrap();

    verifier_index.verify::<BaseSponge, ScalarSponge>(proof, (), public_output);
}
