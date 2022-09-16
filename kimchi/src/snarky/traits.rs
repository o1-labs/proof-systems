//! Traits.

use ark_ff::PrimeField;

use super::{
    checked_runner::{RunState, WitnessGeneration},
    cvar::CVar,
    prelude::TypeCreation,
};

pub trait SnarkyType<F>: Sized
where
    F: PrimeField,
{
    type Auxiliary;
    type OutOfCircuit;

    const SIZE_IN_FIELD_ELEMENTS: usize;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary);

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self;

    fn check(&self, cs: &mut RunState<F>);

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary);

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self;

    fn constraint_system_auxiliary() -> Self::Auxiliary;

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit;

    //
    // new functions that might help us with generics?
    //

    fn compute<FUNC>(
        cs: &mut RunState<F>,
        check: TypeCreation,
        loc: String,
        to_compute_value: FUNC,
    ) -> Self
    where
        FUNC: Fn(&dyn WitnessGeneration<F>) -> Self::OutOfCircuit,
    {
        cs.compute(check, loc, to_compute_value)
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

impl<F, T> SnarkyType<F> for (T, T)
where
    F: PrimeField,
    T: SnarkyType<F>,
{
    type Auxiliary = (T::Auxiliary, T::Auxiliary);

    type OutOfCircuit = (T::OutOfCircuit, T::OutOfCircuit);

    const SIZE_IN_FIELD_ELEMENTS: usize = T::SIZE_IN_FIELD_ELEMENTS * 2;

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
            T::from_cvars_unsafe(cvars1.into_iter().cloned().collect(), aux1),
            T::from_cvars_unsafe(cvars2.into_iter().cloned().collect(), aux2),
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
