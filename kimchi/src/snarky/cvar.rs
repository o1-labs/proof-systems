use std::ops::{Add, Neg, Sub};

use ark_ff::PrimeField;

use crate::snarky::traits::SnarkyType;

use super::{
    checked_runner::{RunState, WitnessGeneration},
    constraint_system::SnarkyCvar,
};

/// A circuit variable represents a field element in the circuit.
#[derive(Clone, Debug)]
pub enum CVar<F>
where
    F: PrimeField,
{
    Constant(F),
    Var(usize),
    Add(Box<CVar<F>>, Box<CVar<F>>),
    Scale(F, Box<CVar<F>>),
}

impl<F> SnarkyCvar for CVar<F>
where
    F: PrimeField,
{
    type Field = F;

    fn to_constant_and_terms(&self) -> (Option<Self::Field>, Vec<(Self::Field, usize)>) {
        self.to_constant_and_terms()
    }
}

pub type Term<F> = (F, usize);

pub type ScaledCVar<F> = (F, CVar<F>);

impl<F> CVar<F>
where
    F: PrimeField,
{
    fn eval_inner(&self, context: &impl (Fn(usize) -> F), scale: F, res: &mut F) {
        match self {
            CVar::Constant(c) => {
                *res += scale * c;
            }
            CVar::Var(v) => {
                let v = context(*v); // TODO: might panic
                *res += scale * v;
            }
            CVar::Add(a, b) => {
                a.eval_inner(context, scale, res);
                b.eval_inner(context, scale, res);
            }
            CVar::Scale(s, v) => {
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

    fn to_constant_and_terms_inner(
        &self,
        scale: F,
        constant: F,
        terms: Vec<Term<F>>,
    ) -> (F, Vec<Term<F>>) {
        match self {
            CVar::Constant(c) => (constant + (scale * c), terms),
            CVar::Var(v) => {
                let mut new_terms = vec![(scale, *v)];
                new_terms.extend(terms);
                (constant, new_terms)
            }
            CVar::Scale(s, t) => t.to_constant_and_terms_inner(scale * s, constant, terms),
            CVar::Add(x1, x2) => {
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
            return CVar::Constant(scalar);
        } else if scalar.is_one() {
            return self.clone();
        }

        match self {
            CVar::Constant(x) => CVar::Constant(*x * scalar),
            CVar::Scale(s, v) => CVar::Scale(*s * scalar, v.clone()),
            CVar::Var(_) | CVar::Add(..) => CVar::Scale(scalar, Box::new(self.clone())),
        }
    }

    pub fn linear_combination(terms: &[ScaledCVar<F>]) -> Self {
        let mut res = CVar::Constant(F::zero());
        for (cst, term) in terms {
            res = res.add(&term.scale(*cst));
        }
        res
    }

    pub fn sum(vs: &[&Self]) -> Self {
        let terms: Vec<_> = vs.iter().map(|v| (F::one(), (*v).clone())).collect();
        Self::linear_combination(&terms)
    }

    pub fn mul(&self, other: &Self, label: Option<&'static str>, cs: &mut RunState<F>) -> Self {
        match (self, other) {
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x * y),

            (CVar::Constant(cst), cvar) | (cvar, CVar::Constant(cst)) => cvar.scale(*cst),

            (_, _) => {
                let self_clone = self.clone();
                let other_clone = other.clone();
                let res: CVar<F> = cs.compute(move |env| {
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
        let one_minus_r = CVar::Constant(F::one()) - &r;
        let zero = CVar::Constant(F::zero());
        state.assert_r1cs(Some("equals_1"), z_inv, z.clone(), one_minus_r);
        state.assert_r1cs(Some("equals_2"), r, z, zero);
    }

    /** [equal_vars z] computes [(r, z_inv)] that satisfy the constraints in
    [equal_constraints z z_inv r].

    In particular, [r] is [1] if [z = 0] and [0] otherwise.
    */
    fn equal_vars(env: &dyn WitnessGeneration<F>, z: &CVar<F>) -> (F, F) {
        let z: F = env.read_var(z);
        if let Some(z_inv) = z.inverse() {
            (F::zero(), z_inv)
        } else {
            (F::one(), F::zero())
        }
    }
}

//
// Our Traits
//

impl<F> SnarkyType<F> for CVar<F>
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = F;

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        (vec![self.clone()], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, _aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), 1);
        cvars[0].clone()
    }

    fn check(&self, _cs: &mut RunState<F>) {
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

//
// Operations
//

impl<F> Add for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (CVar::Constant(x), y) | (y, CVar::Constant(x)) if x.is_zero() => y.clone(),
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x + y),
            (_, _) => CVar::Add(Box::new(self.clone()), Box::new(other.clone())),
        }
    }
}

impl<'a, F> Add<&'a Self> for CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: &Self) -> Self::Output {
        (&self).add(other)
    }
}

impl<F> Add<CVar<F>> for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: CVar<F>) -> Self::Output {
        self.add(&other)
    }
}

impl<F> Sub for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: Self) -> Self::Output {
        match (self, other) {
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x - y),
            _ => self.add(&other.scale(-F::one())),
        }
    }
}

impl<'a, F> Sub<&'a CVar<F>> for CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: &Self) -> Self::Output {
        (&self).sub(other)
    }
}

impl<F> Sub<CVar<F>> for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: CVar<F>) -> Self::Output {
        self.sub(&other)
    }
}

impl<F> Neg for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn neg(self) -> Self::Output {
        self.scale(-F::one())
    }
}
