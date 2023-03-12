use crate::snarky::{
    boolean::Boolean,
    checked_runner::{RunState, WitnessGeneration},
    constraint_system::SnarkyCvar,
    traits::SnarkyType,
};
use ark_ff::PrimeField;
use std::ops::{Add, Neg, Sub};

use super::{
    checked_runner::Constraint,
    constraint_system::BasicSnarkyConstraint,
    poseidon::{CircuitAbsorb, DuplexState},
};

/// A circuit variable represents a field element in the circuit.
#[derive(Clone, Debug)]
pub enum FieldVar<F>
where
    F: PrimeField,
{
    Constant(F),
    Var(usize),
    Add(Box<FieldVar<F>>, Box<FieldVar<F>>),
    Scale(F, Box<FieldVar<F>>),
}

impl<F> SnarkyCvar for FieldVar<F>
where
    F: PrimeField,
{
    type Field = F;

    fn to_constant_and_terms(&self) -> (Option<Self::Field>, Vec<(Self::Field, usize)>) {
        self.to_constant_and_terms()
    }
}

pub type Term<F> = (F, usize);

pub type ScaledCVar<F> = (F, FieldVar<F>);

impl<F> FieldVar<F>
where
    F: PrimeField,
{
    fn eval_inner(&self, context: &impl (Fn(usize) -> F), scale: F, res: &mut F) {
        match self {
            FieldVar::Constant(c) => {
                *res += scale * c;
            }
            FieldVar::Var(v) => {
                let v = context(*v); // TODO: might panic
                *res += scale * v;
            }
            FieldVar::Add(a, b) => {
                a.eval_inner(context, scale, res);
                b.eval_inner(context, scale, res);
            }
            FieldVar::Scale(s, v) => {
                v.eval_inner(context, scale * s, res);
            }
        }
    }

    /// Evaluate the field element associated to a variable (used during witness generation)
    pub fn eval(&self, context: &impl (Fn(usize) -> F)) -> F {
        let mut res = F::zero();
        self.eval_inner(context, F::one(), &mut res);
        res
    }

    pub fn to_constant_and_terms_inner(
        &self,
        scale: F,
        constant: F,
        terms: Vec<Term<F>>,
    ) -> (F, Vec<Term<F>>) {
        match self {
            FieldVar::Constant(c) => (constant + (scale * c), terms),
            FieldVar::Var(v) => {
                let mut new_terms = vec![(scale, *v)];
                new_terms.extend(terms);
                (constant, new_terms)
            }
            FieldVar::Scale(s, t) => t.to_constant_and_terms_inner(scale * s, constant, terms),
            FieldVar::Add(x1, x2) => {
                let (c1, terms1) = x1.to_constant_and_terms_inner(scale, constant, terms);
                x2.to_constant_and_terms_inner(scale, c1, terms1)
            }
        }
    }

    pub fn to_constant_and_terms(&self) -> (Option<F>, Vec<Term<F>>) {
        let (constant, terms) = self.to_constant_and_terms_inner(F::one(), F::zero(), vec![]);
        let constant = if constant.is_zero() {
            None
        } else {
            Some(constant)
        };
        (constant, terms)
    }

    pub fn scale(&self, scalar: F) -> Self {
        if scalar.is_zero() {
            return FieldVar::Constant(scalar);
        } else if scalar.is_one() {
            return self.clone();
        }

        match self {
            FieldVar::Constant(x) => FieldVar::Constant(*x * scalar),
            FieldVar::Scale(s, v) => FieldVar::Scale(*s * scalar, v.clone()),
            FieldVar::Var(_) | FieldVar::Add(..) => FieldVar::Scale(scalar, Box::new(self.clone())),
        }
    }

    pub fn linear_combination(terms: &[ScaledCVar<F>]) -> Self {
        let mut res = FieldVar::Constant(F::zero());
        for (cst, term) in terms {
            res = res.add(&term.scale(*cst));
        }
        res
    }

    pub fn sum(vs: &[&Self]) -> Self {
        let terms: Vec<_> = vs.iter().map(|v| (F::one(), (*v).clone())).collect();
        Self::linear_combination(&terms)
    }

    pub fn mul(
        &self,
        other: &Self,
        label: Option<&'static str>,
        loc: &str,
        cs: &mut RunState<F>,
    ) -> Self {
        match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => FieldVar::Constant(*x * y),

            // TODO: this was not in the original ocaml code, but seems correct to me
            (FieldVar::Constant(cst), _) | (_, FieldVar::Constant(cst)) if cst.is_zero() => {
                FieldVar::Constant(F::zero())
            }

            // TODO: same here
            (FieldVar::Constant(cst), cvar) | (cvar, FieldVar::Constant(cst)) if cst.is_one() => {
                cvar.clone()
            }

            (FieldVar::Constant(cst), cvar) | (cvar, FieldVar::Constant(cst)) => cvar.scale(*cst),

            (_, _) => {
                let self_clone = self.clone();
                let other_clone = other.clone();
                let res: FieldVar<F> = cs.compute(&loc, move |env| {
                    let x: F = env.read_var(&self_clone);
                    let y: F = env.read_var(&other_clone);
                    x * y
                });

                let label = label.or(Some("checked_mul"));

                cs.assert_r1cs(label, self.clone(), other.clone(), res.clone());
                res
            }
        }
    }

    /** [equal_constraints z z_inv r] asserts that
       if z = 0 then r = 1, or
       if z <> 0 then r = 0 and z * z_inv = 1
    */
    fn equal_constraints(state: &mut RunState<F>, z: Self, z_inv: Self, r: Self) {
        // TODO: the ocaml code actually calls assert_all
        let one_minus_r = FieldVar::Constant(F::one()) - &r;
        let zero = FieldVar::Constant(F::zero());
        state.assert_r1cs(Some("equals_1"), z_inv, z.clone(), one_minus_r);
        state.assert_r1cs(Some("equals_2"), r, z, zero);
    }

    /** [equal_vars z] computes [(r, z_inv)] that satisfy the constraints in
    [equal_constraints z z_inv r].

    In particular, [r] is [1] if [z = 0] and [0] otherwise.
    */
    fn equal_vars(env: &dyn WitnessGeneration<F>, z: &FieldVar<F>) -> (F, F) {
        let z: F = env.read_var(z);
        if let Some(z_inv) = z.inverse() {
            (F::zero(), z_inv)
        } else {
            (F::one(), F::zero())
        }
    }

    pub fn equal(&self, state: &mut RunState<F>, loc: &str, other: &FieldVar<F>) -> Boolean<F> {
        match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => {
                let res = if x == y { F::one() } else { F::zero() };
                let cvars = vec![FieldVar::Constant(res)];
                Boolean::from_cvars_unsafe(cvars, ())
            }
            _ => {
                let z = self - other;
                let z_clone = z.clone();
                let (res, z_inv): (FieldVar<F>, FieldVar<F>) =
                    state.compute(loc, move |env| Self::equal_vars(env, &z_clone));
                Self::equal_constraints(state, z, z_inv, res.clone());

                let cvars = vec![res];
                Boolean::from_cvars_unsafe(cvars, ())
            }
        }
    }

    /// Seals the value of a variable.
    ///
    /// As a [`FieldVar`] can represent an AST,
    /// it might not be a good idea to clone it and reuse it in several places.
    /// This is because the exact same reduction that will eventually happen on each clone
    /// will end up creating the same set of constraints multiple times in the circuit.
    ///
    /// It is useful to call [`seal`] on a variable that represents a long computation
    /// that hasn't been constrained yet (e.g. by an assert call, or a call to a custom gate),
    /// before using it further in the circuit.
    pub fn seal(&self, state: &mut RunState<F>, loc: &str) -> Self {
        match self.to_constant_and_terms() {
            (None, terms) if terms.len() == 1 && terms[0].0.is_one() => FieldVar::Var(terms[0].1),
            (Some(c), terms) if terms.is_empty() => FieldVar::Constant(c),
            _ => {
                let y: FieldVar<F> = state.compute(loc, |env| env.read_var(self));
                // this call will reduce [self]
                self.assert_equals(state, loc, &y);
                y
            }
        }
    }
}

//
// Our Traits
//

impl<F> SnarkyType<F> for FieldVar<F>
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = F;

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (vec![self.clone()], ())
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, _aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), 1);
        cvars[0].clone()
    }

    fn check(&self, _cs: &mut super::checked_runner::RunState<F>) {
        // do nothing
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![*x], ())
    }

    fn value_of_field_elements(fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {
        assert_eq!(fields.len(), 1);

        fields[0]
    }
}

impl<F> CircuitAbsorb<F> for FieldVar<F>
where
    F: PrimeField,
{
    fn absorb(&self, duplex: &mut DuplexState<F>, sys: &mut RunState<F>) {
        duplex.absorb(sys, &[self.clone()]);
    }
}

//
// Assertions
//

impl<F> FieldVar<F>
where
    F: PrimeField,
{
    pub fn assert_equals(&self, state: &mut RunState<F>, _loc: &str, other: &FieldVar<F>) {
        state.add_constraint(
            Constraint::BasicSnarkyConstraint(BasicSnarkyConstraint::Equal(
                self.clone(),
                other.clone(),
            )),
            Some("assert equals"),
        );
    }
}

//
// Operations
//

impl<F> Add for &FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (FieldVar::Constant(x), y) | (y, FieldVar::Constant(x)) if x.is_zero() => y.clone(),
            (FieldVar::Constant(x), FieldVar::Constant(y)) => FieldVar::Constant(*x + y),
            (_, _) => FieldVar::Add(Box::new(self.clone()), Box::new(other.clone())),
        }
    }
}

impl<F> Add<Self> for FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn add(self, other: Self) -> Self::Output {
        self.add(&other)
    }
}

impl<'a, F> Add<&'a Self> for FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn add(self, other: &Self) -> Self::Output {
        (&self).add(other)
    }
}

impl<F> Add<FieldVar<F>> for &FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn add(self, other: FieldVar<F>) -> Self::Output {
        self.add(&other)
    }
}

impl<F> Sub for &FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn sub(self, other: Self) -> Self::Output {
        match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => FieldVar::Constant(*x - y),
            // TODO: why not just create a Sub variant?
            _ => self.add(&other.scale(-F::one())),
        }
    }
}

impl<F> Sub<FieldVar<F>> for FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn sub(self, other: FieldVar<F>) -> Self::Output {
        self.sub(&other)
    }
}

impl<'a, F> Sub<&'a FieldVar<F>> for FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn sub(self, other: &Self) -> Self::Output {
        (&self).sub(other)
    }
}

impl<F> Sub<FieldVar<F>> for &FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn sub(self, other: FieldVar<F>) -> Self::Output {
        self.sub(&other)
    }
}

impl<F> Neg for &FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn neg(self) -> Self::Output {
        self.scale(-F::one())
    }
}

impl<F> Neg for FieldVar<F>
where
    F: PrimeField,
{
    type Output = FieldVar<F>;

    fn neg(self) -> Self::Output {
        self.scale(-F::one())
    }
}
