use self::instance::{Instance, RelaxedInstance};
use super::{poseidon::DuplexState, prelude::*};
use crate::{
    curve::KimchiCurve,
    loc,
    snarky::{api::SnarkyCircuit, cvar::FieldVar, runner::RunState},
};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField};
use core::{marker::PhantomData, ops::Add};
use mina_curves::pasta::Fp;
use poly_commitment::{ipa::OpeningProof, OpenProof};

mod instance;

const CHALLENGE_BITS: usize = 127;

struct FoldingCircuit<C: KimchiCurve, P: OpenProof<C>, const N: usize> {
    _field: PhantomData<C>,
    _proof: PhantomData<P>,
    /// Commitment sets and their sizes
    commitments: Vec<usize>,
    /// Challenges sets and their sizes
    challenges: Vec<usize>,
}

/// The value of the input an output of the function being folded
struct Argument<F, const N: usize>([F; N]);

type Point<F> = [F; 2];

/// Represents the result of a (Poseidon) hash, encoded in the circuit
type Hash<F> = FieldVar<F>;

/// Represents an element of the other curve's field. As the other field can
/// have a higher order, it could require more than one limbs. We suppose the
/// other field values can be encoded on two limbs.
#[derive(Debug, Clone)]
pub struct ForeignElement<F>([F; 2]);

/// A challenge encoded on 127 bits
#[derive(Debug, Clone)]
struct SmallChallenge<F: PrimeField>(FieldVar<F>);

#[derive(Debug, Clone)]
pub struct FullChallenge<F>(ForeignElement<F>);

pub struct Private<F, const N: usize> {
    /// First input
    z_0: Argument<F, N>,
    /// Input for this step and output of the previous one
    z_i: Argument<F, N>,
    /// All instances accumulated so far
    u_acc: RelaxedInstance<F>,
    /// Newest instance to be folded into the accumulated instance
    u_i: Instance<F>,
    /// 2 commitments to error terms to be used when folding the error column
    t: [Point<F>; 2],
    i: F,
}

/// This should run the inner circuit and provide its output, in our case it may be simpler
/// to just run the circuit separatly and provide the variables pointing to the output
fn apply<F: PrimeField, const N: usize>(
    _z_i: Argument<FieldVar<F>, N>,
) -> Argument<FieldVar<F>, N> {
    // TODO
    todo!()
}

type F<C> = <C as AffineRepr>::ScalarField;

fn challenge_linear_combination<F: PrimeField>(
    _full: FullChallenge<FieldVar<F>>,
    _small: SmallChallenge<F>,
    _combiner: &SmallChallenge<F>,
) -> FullChallenge<FieldVar<F>> {
    // TODO
    todo!()
}

fn commitment_linear_combination<F: PrimeField>(
    _a: Point<FieldVar<F>>,
    _b: Point<FieldVar<F>>,
    _combiner: &SmallChallenge<F>,
) -> Point<FieldVar<F>> {
    // TODO
    todo!()
}
fn ec_add<F: PrimeField>(_a: Point<FieldVar<F>>, _b: Point<FieldVar<F>>) -> Point<FieldVar<F>> {
    // TODO
    todo!()
}
fn ec_scale<F: PrimeField>(
    _point: Point<FieldVar<F>>,
    _scalar: &SmallChallenge<F>,
) -> Point<FieldVar<F>> {
    // TODO
    todo!()
}

/// Trims to 127 bits
fn trim<F: PrimeField>(
    sys: &mut RunState<F>,
    v: &FieldVar<F>,
    base: &FieldVar<F>,
) -> SnarkyResult<FieldVar<F>> {
    let (high, low): (FieldVar<F>, FieldVar<F>) = sys.compute(loc!(), |wit| {
        let val = wit.read_var(v);
        let mut high = val.into_bigint();
        high.divn(CHALLENGE_BITS as u32);
        let mut low = val.into_bigint();
        low.sub_with_borrow(&high);
        (F::from_bigint(high).unwrap(), F::from_bigint(low).unwrap())
    })?;
    let composition = high.mul(base, None, loc!(), sys)? + &low;
    // TODO: constraint low to 127 bits
    v.assert_equals(sys, loc!(), &composition)?;
    Ok(low)
}

/// Compute H(i, z_0, z_1, u) and keep the log2(base) bits of the result.
/// [base] is supposed to be a power of 2
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

impl<C: KimchiCurve, P: OpenProof<C>, const N: usize> SnarkyCircuit for FoldingCircuit<C, P, N> {
    type Curve = C;
    type Proof = P;

    type PrivateInput = Private<F<C>, N>;
    type PublicInput = ();
    type PublicOutput = [Hash<F<C>>; 2];

    /// Implement the IVC circuit, see https://eprint.iacr.org/2021/370.pdf, Fig
    /// 4, page 18
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
    use mina_curves::pasta::{Vesta, VestaParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

    let circuit = FoldingCircuit {
        _field: PhantomData,
        _proof: PhantomData::<OpeningProof<Vesta>>,
        commitments: vec![15],
        challenges: vec![1, 5],
    };
    let (mut prover_index, verifier_index) = circuit.compile_to_indexes().unwrap();
    let (proof, public_output) = prover_index
        .prove::<BaseSponge, ScalarSponge>((), private, true)
        .unwrap();

    verifier_index.verify::<BaseSponge, ScalarSponge>(proof, (), *public_output);
}
