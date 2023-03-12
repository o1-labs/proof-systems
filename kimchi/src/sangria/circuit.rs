use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;
use snarky_deriver::SnarkyType;

use crate::circuits::polynomials::generic::GENERIC_REGISTERS;
use crate::curve::KimchiCurve;
use crate::snarky::poseidon::{CircuitAbsorb, DuplexState};
use crate::snarky::prelude::*;

// Remember:
//
// |Fq| > |Fp|
//
// The strategy here is to implement two different circuits that both do the verifier side of the folding,
// but where only one of them (the Vesta/Fp one) has application logic.
//

//
// Data structures
//

#[derive(Debug, SnarkyType)]
pub struct CurvePoint<F>
where
    F: PrimeField,
{
    x: FieldVar<F>,
    y: FieldVar<F>,
    point_at_infinity: Boolean<F>,
}

impl<F> CurvePoint<F>
where
    F: PrimeField,
{
    pub fn scale(&self, sys: &mut RunState<F>, loc: &str, scalar_bits: &FieldVar<F>) -> Self {
        todo!()
    }

    pub fn add(&self, sys: &mut RunState<F>, loc: &str, other: &Self) -> Self {
        todo!()
    }
}

impl<F> CircuitAbsorb<F> for CurvePoint<F>
where
    F: PrimeField,
{
    fn absorb(&self, duplex: &mut DuplexState<F>, sys: &mut RunState<F>) {
        self.x.absorb(duplex, sys);
        self.y.absorb(duplex, sys);
        self.point_at_infinity.absorb(duplex, sys);
    }
}

/// A sangria proof, equivalent to [`SangriaProof`].
#[derive(Debug, SnarkyType)]
#[snarky(field = "G::ScalarField")]
pub struct CircuitSangriaProof<G>
where
    G: KimchiCurve,
{
    t_commit: CurvePoint<G::ScalarField>,
}

/// Equivalent to [`SangriaIstance`].
#[derive(Debug, SnarkyType)]
// TODO: implement out-of-circuit conversion
//#[snarky(out_of_circuit = "SangriaInstance<G: G::ScalarField = F>")]
pub struct CircuitSangriaInstance<F>
where
    F: PrimeField,
{
    public_input: CurvePoint<F>,
    relaxing_factor: FieldVar<F>,
    register_commitments: [CurvePoint<F>; GENERIC_REGISTERS],
    slack_commitment: CurvePoint<F>,
}

impl<F> CircuitAbsorb<F> for CircuitSangriaInstance<F>
where
    F: PrimeField,
{
    fn absorb(&self, duplex: &mut DuplexState<F>, sys: &mut RunState<F>) {
        self.public_input.absorb(duplex, sys);
        self.relaxing_factor.absorb(duplex, sys);
        for commitment in self.register_commitments.iter() {
            commitment.absorb(duplex, sys);
        }
        self.slack_commitment.absorb(duplex, sys);
    }
}

// TODO: implement out-of-circuit conversion

// impl<G> From<(Vec<G::ScalarField>, ())> for SangriaInstance<G>
// where
//     G: KimchiCurve,
//     G::ScalarField: PrimeField,
// {
//     fn from((fields, _): (Vec<G::ScalarField>, ())) -> Self {
//         let mut fields = fields.into_iter();
//         // TODO: consume the iterator to get the values
//         Self {
//             public_input: todo!(),
//             relaxing_factor: todo!(),
//             register_commitments: todo!(),
//             slack_commitment: todo!(),
//         }
//     }
// }

// impl<G> From<SangriaInstance<G>> for (Vec<G::ScalarField>, ())
// where
//     G: KimchiCurve,
//     G::ScalarField: PrimeField,
// {
//     fn from(instance: SangriaInstance<G>) -> Self {
//         todo!()
//     }
// }

/// Lazy once_cell computation of 2^128
static TWO_TO_128: once_cell::sync::Lazy<BigUint> =
    once_cell::sync::Lazy::new(|| BigUint::from(2u64).pow(128));

/// Helper to truncate a value to 128 bits.
fn truncate_to_128<F>(sys: &mut RunState<F>, value: FieldVar<F>) -> FieldVar<F>
where
    F: PrimeField,
{
    // ask the prover to do `original_value = (hi, lo)` in their head
    let (hi, lo): (FieldVar<F>, FieldVar<F>) = sys.compute(&loc!(), |env| {
        let value = value.read(env);

        // to get the higher 128 bits we mutate the u64 array
        let mut arkworks_bigint = value.into_repr().clone();
        let u64_array = arkworks_bigint.as_mut();
        u64_array[0] = 0;
        u64_array[1] = 0;
        let hi = F::try_from(arkworks_bigint).unwrap();

        // to get the lower 128 bits we use num_bigint
        let bigint: BigUint = value.into();
        let lo = bigint.mod_floor(&TWO_TO_128);
        let lo = F::try_from(lo).unwrap();

        (hi, lo)
    });

    // TODO: range check that `lo` and `hi` are 128-bit values.
    lo.is_n_bits(sys, &loc!(), 128);
    hi.is_n_bits(sys, &loc!(), 128);

    // then verify that `lo + 2^128 * hi = original_value`
    let two_to_128 = FieldVar::constant(F::from(2u64).pow(&[128u64]));
    let res = two_to_128.mul(&hi, None, &loc!(), sys) + &lo;
    res.assert_equals(sys, &loc!(), &value);

    // return the truncated lower 128 bits
    lo
}

pub struct DeferredComputation<F>
where
    F: PrimeField,
{
    computed_folded_u: FieldVar<F>,
    from_u1: FieldVar<F>,
    from_u2: FieldVar<F>,
    from_r: FieldVar<F>,
}

pub struct CircuitOption<F, T>
where
    F: PrimeField,
{
    set: Boolean<F>,
    val: T,
}

pub fn verifier_fold<G>(
    sys: &mut RunState<G::ScalarField>,
    instance1: CircuitSangriaInstance<G::ScalarField>,
    instance2: CircuitSangriaInstance<G::ScalarField>,
    proof: CircuitSangriaProof<G>,
    deferred: CircuitOption<G::ScalarField, DeferredComputation<G::ScalarField>>,
) -> (
    CircuitSangriaInstance<G::ScalarField>,
    DeferredComputation<G::ScalarField>,
)
where
    G: KimchiCurve,
{
    // TODO: absorb everything (I'm still missing some fields)
    let mut duplex = DuplexState::new();

    // absorb instances
    instance1.absorb(&mut duplex, sys);
    instance2.absorb(&mut duplex, sys);

    // absorb proof and get challenge
    proof.t_commit.absorb(&mut duplex, sys);
    let challenge = duplex.squeeze(sys);

    // TODO: challenge must be a scalar, so get 128 first bits?
    let challenge = truncate_to_128(sys, challenge);

    // fold the public input
    let r_pub2 = instance2.public_input.scale(sys, &loc!(), &challenge);
    let public_input = instance1.public_input.add(sys, &loc!(), &r_pub2);

    // fold the scaling factor
    let relaxing_factor: FieldVar<G::ScalarField> = sys.compute(&loc!(), |env| {
        // TODO: these tuples suck, but without a deriver that understands structured out-of-circuit types, we are limited to tuples
        let (_, relaxing_factor1, _, _) = SnarkyType::read(&instance1, env);
        let (_, relaxing_factor2, _, _) = SnarkyType::read(&instance2, env);
        let challenge = SnarkyType::read(&challenge, env);
        relaxing_factor1 + (relaxing_factor2 * &challenge)
    });
    let deferred = DeferredComputation {
        computed_folded_u: relaxing_factor.clone(),
        from_u1: instance1.relaxing_factor.clone(),
        from_u2: instance2.relaxing_factor.clone(),
        from_r: challenge.clone(),
    };

    // fold the register commitments
    let register_commitments = instance1
        .register_commitments
        .iter()
        .zip(&instance2.register_commitments)
        .map(|(c1, c2)| {
            let r_c2 = c2.scale(sys, &loc!(), &challenge);
            c1.add(sys, &loc!(), &r_c2)
        })
        .collect::<Vec<_>>();

    // compute new E commitment

    // return new instance and deferred computation
    let folded_instance = CircuitSangriaInstance {
        public_input,
        relaxing_factor: instance1.relaxing_factor,
        register_commitments: instance1.register_commitments,
        slack_commitment: instance1.slack_commitment,
    };

    // return
    (folded_instance, deferred)
}
