//! Traits.

use ark_ff::PrimeField;

use super::{
    checked_runner::{RunState, WitnessGeneration},
    cvar::CVar,
};

/// A snarky type is a type that can be used in a circuit.
/// It references an equivalent "out-of-circuit" type that one can use outside of the circuit.
/// (For example, to construct private or public inputs, or a public output, to the circuit.)
pub trait SnarkyType<F>: Sized
where
    F: PrimeField,
{
    /// Some additional information. (TODO: add more documentation.)
    type Auxiliary;

    /// The equivalent "out-of-circuit" type.
    /// For example, the [super::boolean::Boolean] snarky type has an out-of-circuit type of [bool].
    type OutOfCircuit;

    /// The number of field elements that this type takes.
    const SIZE_IN_FIELD_ELEMENTS: usize;

    /// Returns the circuit variables (and auxiliary data) behind this type.
    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary);

    /// Creates a new instance of this type from the given circuit variables (And some auxiliary data).
    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self;

    /// Checks that the circuit variables behind this type are valid.
    /// For some definition of valid.
    /// For example, a Boolean snarky type would check that the field element representing it is either 0 or 1.
    /// The function does this by adding constraints to your constraint system.
    fn check(&self, cs: &mut RunState<F>);

    /// Deserializes this type into the out-of-circuit type (along with some auxiliary data).
    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary);

    /// Serializes the out-of-circuit type (along with some auxiliary data) into this type.
    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self;

    /// Returns some auxiliary data (TODO: more doc).
    fn constraint_system_auxiliary() -> Self::Auxiliary;

    ///
    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit;

    //
    // new functions that might help us with generics?
    //

    fn compute<FUNC>(cs: &mut RunState<F>, loc: String, to_compute_value: FUNC) -> Self
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
        Self::value_of_field_elements((values, aux))
    }
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

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        (vec![], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self {
        ()
    }

    fn check(&self, cs: &mut RunState<F>) {}

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary) {
        ((), ())
    }

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self {
        ()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        ()
    }

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![], ())
    }

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit {
        ()
    }
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

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        let (mut cvars1, aux1) = self.0.to_cvars();
        let (cvars2, aux2) = self.1.to_cvars();
        cvars1.extend(cvars2);
        (cvars1, (aux1, aux2))
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);
        let (cvars1, cvars2) = cvars.split_at(Self::SIZE_IN_FIELD_ELEMENTS);
        let (aux1, aux2) = aux;
        (
            T1::from_cvars_unsafe(cvars1.into_iter().cloned().collect(), aux1),
            T2::from_cvars_unsafe(cvars2.into_iter().cloned().collect(), aux2),
        )
    }

    fn check(&self, cs: &mut RunState<F>) {
        self.0.check(cs);
        self.1.check(cs);
    }

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary) {
        todo!()
    }

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self {
        todo!()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        todo!()
    }

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        todo!()
    }

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit {
        todo!()
    }
}
