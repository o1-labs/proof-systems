//! The [SnarkyType] trait is a useful trait that allows us to define our own
//! snarky variables on top of [FieldVar].
//! Without it, we'd be limited to using the [FieldVar] type directly, handling
//! and returning arrays of [FieldVar]s all the time.
//! So this is useful for the same reason that programming languages allow users
//! to define their own types, instead of relying only on `usize`.
//!
//! To define your own snarky type, implement the `SnarkyType` trait.
//! A good example is the `Boolean` type.

use super::{
    cvar::FieldVar,
    errors::SnarkyResult,
    runner::{RunState, WitnessGeneration},
};

use ark_ff::PrimeField;

use std::{borrow::Cow, fmt::Debug};

/// A snarky type is a type that can be used in a circuit.
/// It references an equivalent "out-of-circuit" type that one can use outside of the circuit.
/// (For example, to construct private or public inputs, or a public output, to the circuit.)
pub trait SnarkyType<F>: Debug + Sized
where
    F: PrimeField,
{
    /// Some 'out-of-circuit' data, which is carried as part of Self.
    /// This data isn't encoded as CVars in the circuit, since the data may be large (e.g. a sparse merkle tree),
    /// or may only be used by witness computations / for debugging.
    type Auxiliary;

    /// The equivalent "out-of-circuit" type.
    /// For example, the [super::boolean::Boolean] snarky type has an out-of-circuit type of [bool].
    type OutOfCircuit;

    /// The number of field elements that this type takes.
    const SIZE_IN_FIELD_ELEMENTS: usize;

    /// Returns the circuit variables (and auxiliary data) behind this type.
    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary);

    /// Creates a new instance of this type from the given circuit variables (And some auxiliary data).
    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self;

    /// Checks that the circuit variables behind this type are valid.
    /// For some definition of valid.
    /// For example, a Boolean snarky type would check that the field element representing it is either 0 or 1.
    /// The function does this by adding constraints to your constraint system.
    fn check(&self, cs: &mut RunState<F>, loc: Cow<'static, str>) -> SnarkyResult<()>;

    /// The "default" value of [Self::Auxiliary].
    /// This is passed to [Self::from_cvars_unsafe] when we are not generating a witness,
    /// since we have no candidate value to get the auxiliary data from.
    /// Note that we use an explicit value here rather than Auxiliary: Default,
    /// since the default value for the type may not match the default value we actually want to pass!
    fn constraint_system_auxiliary() -> Self::Auxiliary;

    /// Converts an out-of-circuit value
    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);

    fn value_of_field_elements(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit;

    //
    // new functions that might help us with generics?
    //

    fn compute<FUNC>(
        cs: &mut RunState<F>,
        loc: Cow<'static, str>,
        to_compute_value: FUNC,
    ) -> SnarkyResult<Self>
    where
        FUNC: Fn(&dyn WitnessGeneration<F>) -> Self::OutOfCircuit,
    {
        cs.compute(loc, to_compute_value)
    }

    fn read<G>(&self, g: G) -> Self::OutOfCircuit
    where
        G: WitnessGeneration<F>,
    {
        let (cvars, aux) = self.to_cvars();
        let values = cvars.iter().map(|cvar| g.read_var(cvar)).collect();
        Self::value_of_field_elements(values, aux)
    }
}

/// A trait to convert between a snarky type and its out-of-circuit equivalent.
// TODO: should we then remove these functions + OutOfCircuit from SnarkyType? (And have SnarkyType : CircuitAndValue)
pub trait CircuitAndValue<F>: SnarkyType<F>
where
    F: PrimeField,
{
    fn to_value(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit;
    fn from_value(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);
}

//
// Auto traits
//

impl<F> SnarkyType<F> for ()
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = ();

    const SIZE_IN_FIELD_ELEMENTS: usize = 0;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (vec![], ())
    }

    fn from_cvars_unsafe(_cvars: Vec<FieldVar<F>>, _aux: Self::Auxiliary) -> Self {}

    fn check(&self, _cs: &mut RunState<F>, _loc: Cow<'static, str>) -> SnarkyResult<()> {
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(_value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![], ())
    }

    fn value_of_field_elements(_fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {}
}

impl<F, T1, T2> SnarkyType<F> for (T1, T2)
where
    F: PrimeField,
    T1: SnarkyType<F>,
    T2: SnarkyType<F>,
{
    type Auxiliary = (T1::Auxiliary, T2::Auxiliary);

    type OutOfCircuit = (T1::OutOfCircuit, T2::OutOfCircuit);

    const SIZE_IN_FIELD_ELEMENTS: usize = T1::SIZE_IN_FIELD_ELEMENTS + T2::SIZE_IN_FIELD_ELEMENTS;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        let (mut cvars1, aux1) = self.0.to_cvars();
        let (cvars2, aux2) = self.1.to_cvars();
        cvars1.extend(cvars2);
        (cvars1, (aux1, aux2))
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);
        let (cvars1, cvars2) = cvars.split_at(T1::SIZE_IN_FIELD_ELEMENTS);
        let (aux1, aux2) = aux;
        (
            T1::from_cvars_unsafe(cvars1.to_vec(), aux1),
            T2::from_cvars_unsafe(cvars2.to_vec(), aux2),
        )
    }

    fn check(&self, cs: &mut RunState<F>, loc: Cow<'static, str>) -> SnarkyResult<()> {
        self.0.check(cs, loc.clone())?;
        self.1.check(cs, loc)?;
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        (
            T1::constraint_system_auxiliary(),
            T2::constraint_system_auxiliary(),
        )
    }

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        let (mut fields, aux1) = T1::value_to_field_elements(&value.0);
        let (fields2, aux2) = T2::value_to_field_elements(&value.1);
        fields.extend(fields2);
        (fields, (aux1, aux2))
    }

    fn value_of_field_elements(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
        let (fields1, fields2) = fields.split_at(T1::SIZE_IN_FIELD_ELEMENTS);

        let out1 = T1::value_of_field_elements(fields1.to_vec(), aux.0);
        let out2 = T2::value_of_field_elements(fields2.to_vec(), aux.1);

        (out1, out2)
    }
}

impl<F, T, const N: usize> SnarkyType<F> for [T; N]
where
    F: PrimeField,
    T: SnarkyType<F>,
{
    // TODO: convert this to a `[T::Auxiliary; N]`
    type Auxiliary = Vec<T::Auxiliary>;

    type OutOfCircuit = [T::OutOfCircuit; N];

    const SIZE_IN_FIELD_ELEMENTS: usize = N * T::SIZE_IN_FIELD_ELEMENTS;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        let (cvars, aux): (Vec<Vec<_>>, Vec<_>) = self.iter().map(|t| t.to_cvars()).unzip();
        let cvars = cvars.concat();
        (cvars, aux)
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self {
        let mut cvars_and_aux = cvars.chunks(T::SIZE_IN_FIELD_ELEMENTS).zip(aux);

        core::array::from_fn(|_| {
            let (cvars, aux) = cvars_and_aux.next().unwrap();
            assert_eq!(cvars.len(), T::SIZE_IN_FIELD_ELEMENTS);
            T::from_cvars_unsafe(cvars.to_vec(), aux)
        })
    }

    fn check(&self, cs: &mut RunState<F>, loc: Cow<'static, str>) -> SnarkyResult<()> {
        for t in self.iter() {
            t.check(cs, loc.clone())?;
        }
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        let mut aux = Vec::with_capacity(T::SIZE_IN_FIELD_ELEMENTS);
        for _ in 0..N {
            aux.push(T::constraint_system_auxiliary());
        }
        aux
    }

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        let (fields, aux): (Vec<Vec<_>>, Vec<_>) =
            value.iter().map(|v| T::value_to_field_elements(v)).unzip();
        (fields.concat(), aux)
    }

    fn value_of_field_elements(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
        let mut values_and_aux = fields.chunks(T::SIZE_IN_FIELD_ELEMENTS).zip(aux);

        core::array::from_fn(|_| {
            let (fields, aux) = values_and_aux.next().unwrap();
            assert_eq!(fields.len(), T::SIZE_IN_FIELD_ELEMENTS);
            T::value_of_field_elements(fields.to_vec(), aux)
        })
    }
}
