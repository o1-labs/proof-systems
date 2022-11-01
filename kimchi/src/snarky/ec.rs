use crate::snarky::{cvar::CVar, prelude::RunState, traits::SnarkyType};
use ark_ff::PrimeField;

#[derive(Clone)]
pub struct Point<F: PrimeField> {
    x: CVar<F>,
    y: CVar<F>,
}
#[derive(Clone)]
pub struct OutOfCircuitPoint<F: PrimeField> {
    x: F,
    y: F,
}

impl<F: PrimeField> SnarkyType<F> for Point<F> {
    type Auxiliary = ();

    type OutOfCircuit = OutOfCircuitPoint<F>;

    const SIZE_IN_FIELD_ELEMENTS: usize = 2;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        let Self { x, y } = self.clone();
        (vec![x, y], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, _aux: Self::Auxiliary) -> Self {
        let [x, y]: [_; 2] = cvars.try_into().unwrap();
        Self { x, y }
    }

    fn check(&self, cs: &mut RunState<F>) {
        //from pasta law: y^2 = x^3 + 5
        let Self { x, y } = self.clone();
        let x_square = x.mul(&x, None, cs);
        let x_cube = x_square.mul(&x, None, cs);
        let y_square = y.mul(&y, None, cs);
        cs.assert_eq(None, y_square, x_cube + &CVar::Constant(5_u32.into()));
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        let Self::OutOfCircuit { x, y } = value.clone();
        (vec![x, y], ())
    }

    fn value_of_field_elements(fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {
        let [x, y]: [F; 2] = fields.try_into().unwrap();
        Self::OutOfCircuit { x, y }
    }
}

impl<F: PrimeField> Point<F> {
    pub fn add(&self, other: &Self, cs: &mut RunState<F>) -> Self {
        let (x, y): (CVar<_>, CVar<_>) = cs.compute("".into(), |env| {
            let from_point = |point: &Point<_>| {
                let x = env.read_var(&point.x);
                let y = env.read_var(&point.y);
                OutOfCircuitPoint { x, y }
            };
            let a = from_point(self);
            let b = from_point(other);
            //todo add constraint
            sum(a, b)
        });
        Point { x, y }
    }
    //todo: add the other gates
}

fn sum<F: PrimeField>(_a: OutOfCircuitPoint<F>, _b: OutOfCircuitPoint<F>) -> (F, F) {
    todo!()
}
