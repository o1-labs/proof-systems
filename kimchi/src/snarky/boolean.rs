use ark_ff::PrimeField;

use crate::{
    loc,
    snarky::{
        checked_runner::RunState, constraint_system::BasicSnarkyConstraint, cvar::CVar,
        traits::SnarkyType,
    },
};

trait OutOfCircuitSnarkyType2<F> {
    type InCircuit;
}

impl<F> OutOfCircuitSnarkyType2<F> for bool
where
    F: PrimeField,
{
    type InCircuit = Boolean<F>;
}

/// A boolean variable.
#[derive(Clone)]
pub struct Boolean<F: PrimeField>(CVar<F>);

impl<F> SnarkyType<F> for Boolean<F>
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = bool;

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        (vec![self.0.clone()], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, _aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);
        Self(cvars[0].clone())
    }

    fn check(&self, cs: &mut RunState<F>) {
        // TODO: annotation?
        cs.assert_(None, vec![BasicSnarkyConstraint::Boolean(self.0.clone())]);
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

impl<F> Boolean<F>
where
    F: PrimeField,
{
    pub fn true_() -> Self {
        Self(CVar::Constant(F::one()))
    }

    pub fn false_() -> Self {
        Self(CVar::Constant(F::zero()))
    }

    pub fn not(&self) -> Self {
        Self(Self::true_().0 - &self.0)
    }

    pub fn if_(&self, then_: Self, else_: Self) -> Self {
        todo!()
    }

    pub fn and(&self, other: &Self, cs: &mut RunState<F>) -> Self {
        Self(self.0.mul(&other.0, Some("bool.and"), cs))
    }

    pub fn or(&self, other: &Self, cs: &mut RunState<F>) -> Self {
        let both_false = self.not().and(&other.not(), cs);
        both_false.not()
    }

    pub fn any(xs: &[&Self], cs: &mut RunState<F>) -> Self {
        if xs.is_empty() {
            return Self::false_(); // TODO: shouldn't we panic instead?
        } else if xs.len() == 1 {
            return xs[0].clone();
        } else if xs.len() == 2 {
            return xs[0].or(&xs[1], cs); // TODO: is this better than below?
        }

        let zero = CVar::Constant(F::zero());

        let xs: Vec<_> = xs.into_iter().map(|x| &x.0).collect();
        let sum = CVar::sum(&xs);
        let all_zero = sum.equal(cs, &zero);

        all_zero.not()
    }

    pub fn all(xs: &[Self], cs: &mut RunState<F>) -> Self {
        if xs.is_empty() {
            return Self::true_(); // TODO: shouldn't we panic instead?
        } else if xs.len() == 1 {
            return xs[0].clone();
        } else if xs.len() == 2 {
            return xs[0].and(&xs[1], cs); // TODO: is this better than below?
        }

        let expected = CVar::Constant(F::from(xs.len() as u64));
        let xs: Vec<_> = xs.iter().map(|x| &x.0).collect();
        let sum = CVar::sum(&xs);

        sum.equal(cs, &expected)
    }

    pub fn to_constant(&self) -> Option<bool> {
        match self.0 {
            CVar::Constant(x) => Some(x == F::one()),
            _ => None,
        }
    }

    pub fn xor(&self, other: &Self, state: &mut RunState<F>) -> Self {
        match (self.to_constant(), other.to_constant()) {
            (Some(x), Some(y)) => {
                // (var_of_value (Caml.not (Bool.equal b1 b2)))
                todo!()
            }
            (Some(true), None) => other.not(),
            (None, Some(true)) => self.not(),
            (Some(false), None) => other.clone(),
            (None, Some(false)) => self.clone(),
            (None, None) => {
                /*
                   (1 - 2 a) (1 - 2 b) = 1 - 2 c
                1 - 2 (a + b) + 4 a b = 1 - 2 c
                - 2 (a + b) + 4 a b = - 2 c
                (a + b) - 2 a b = c
                2 a b = a + b - c
                 */

                let self_clone = self.clone();
                let other_clone = other.clone();
                let res: Boolean<F> = state.compute_unsafe(loc!(), move |env| {
                    let b1: bool = self_clone.read(env);
                    let b2: bool = other_clone.read(env);

                    /*
                    let%bind res =
                      exists typ_unchecked
                        ~compute:
                          As_prover.(
                            map2 ~f:Bool.( <> ) (read typ_unchecked b1)
                              (read typ_unchecked b2))
                    in
                     */

                    todo!()
                });

                let x = &self.0 + &self.0;
                let y = &other.0;
                let z = &self.0 + &other.0 - &res.0;

                // TODO: annotation?
                state.assert_r1cs(None, x, y.clone(), z);

                res
            }
        }
    }
}
