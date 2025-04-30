use super::{
    constraint_system::BasicSnarkyConstraint,
    errors::{SnarkyCompilationError, SnarkyResult},
    runner::Constraint,
};
use crate::snarky::{
    boolean::Boolean,
    constraint_system::SnarkyCvar,
    runner::{RunState, WitnessGeneration},
    snarky_type::SnarkyType,
};
use ark_ff::PrimeField;
use core::ops::{Add, Neg, Sub};
use std::borrow::Cow;

/// A circuit variable represents a field element in the circuit.
/// Note that a [`FieldVar`] currently represents a small AST that can hide nested additions and multiplications of [`FieldVar`]s.
/// The reason behind this decision is that converting additions and multiplications directly into constraints is not optimal.
/// So we most often wait until some additions have been accumulated before reducing them down to constraints.
///
/// Note: this design decision also leads to optimization issues,
/// when we end up cloning and then reducing the same mini-ASTs multiple times.
/// To force reduction of a [`FieldVar`] (most often before cloning),
/// the [Self::seal] function can be used.
#[derive(Clone, Debug)]
pub enum FieldVar<F>
where
    F: PrimeField,
{
    /// A constant (a field element).
    Constant(F),

    /// A variable, tracked by a counter.
    Var(usize),

    /// Addition of two [`FieldVar`]s.
    Add(Box<FieldVar<F>>, Box<FieldVar<F>>),

    /// Multiplication of a [`FieldVar`] by a constant.
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

// TODO: create a real type for this
pub type Term<F> = (F, usize);

// TODO: create a real type for this
pub type ScaledCVar<F> = (F, FieldVar<F>);

impl<F> FieldVar<F>
where
    F: PrimeField,
{
    /// Converts a field element `c` into a [`FieldVar`].
    pub fn constant(c: F) -> Self {
        FieldVar::Constant(c)
    }

    /// Returns the zero constant.
    pub fn zero() -> Self {
        Self::constant(F::zero())
    }

    // TODO: should we cache results to avoid recomputation them again and again?
    fn eval_inner(&self, state: &RunState<F>, scale: F, res: &mut F) {
        match self {
            FieldVar::Constant(c) => {
                *res += scale * c;
            }
            FieldVar::Var(v) => {
                let v = state.read_var_idx(*v);
                *res += scale * v;
            }
            FieldVar::Add(a, b) => {
                a.eval_inner(state, scale, res);
                b.eval_inner(state, scale, res);
            }
            FieldVar::Scale(s, v) => {
                v.eval_inner(state, scale * s, res);
            }
        }
    }

    /// Evaluate the field element associated to a variable (used during witness generation)
    pub fn eval(&self, state: &RunState<F>) -> F {
        let mut res = F::zero();
        self.eval_inner(state, F::one(), &mut res);
        res
    }

    fn to_constant_and_terms_inner(
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
        let mut res = FieldVar::zero();
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
        label: Option<Cow<'static, str>>,
        loc: Cow<'static, str>,
        cs: &mut RunState<F>,
    ) -> SnarkyResult<Self> {
        let res = match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => FieldVar::Constant(*x * y),

            (FieldVar::Constant(cst), cvar) | (cvar, FieldVar::Constant(cst)) => cvar.scale(*cst),

            (_, _) => {
                let self_clone = self.clone();
                let other_clone = other.clone();
                let res: FieldVar<F> = cs.compute(loc.clone(), move |env| {
                    let x: F = env.read_var(&self_clone);
                    let y: F = env.read_var(&other_clone);
                    x * y
                })?;

                let label = label.or(Some("checked_mul".into()));

                cs.assert_r1cs(label, loc, self.clone(), other.clone(), res.clone())?;

                res
            }
        };

        Ok(res)
    }

    /** [equal_constraints z z_inv r] asserts that
       if z = 0 then r = 1, or
       if z <> 0 then r = 0 and z * z_inv = 1
    */
    fn equal_constraints(
        state: &mut RunState<F>,
        loc: Cow<'static, str>,
        z: Self,
        z_inv: Self,
        r: Self,
    ) -> SnarkyResult<()> {
        let one_minus_r = FieldVar::Constant(F::one()) - &r;
        let zero = FieldVar::zero();
        state.assert_r1cs(
            Some("equals_1".into()),
            loc.clone(),
            z_inv,
            z.clone(),
            one_minus_r,
        )?;
        state.assert_r1cs(Some("equals_2".into()), loc, r, z, zero)
    }

    /** `z` computes `(r, z_inv)` that satisfy the constraints in
    [Self::equal_constraints] `z` `z_inv` `r`.

    In particular, `r` is `1` if `z = 0` and `0` otherwise.
    */
    fn equal_vars(env: &dyn WitnessGeneration<F>, z: &FieldVar<F>) -> (F, F) {
        let z: F = env.read_var(z);
        if let Some(z_inv) = z.inverse() {
            (F::zero(), z_inv)
        } else {
            (F::one(), F::zero())
        }
    }

    pub fn equal(
        &self,
        state: &mut RunState<F>,
        loc: Cow<'static, str>,
        other: &FieldVar<F>,
    ) -> SnarkyResult<Boolean<F>> {
        let res = match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => {
                if x == y {
                    Boolean::true_()
                } else {
                    Boolean::false_()
                }
            }
            _ => {
                let z = self - other;
                let z_clone = z.clone();
                let (res, z_inv): (FieldVar<F>, FieldVar<F>) =
                    state.compute(loc.clone(), move |env| Self::equal_vars(env, &z_clone))?;
                Self::equal_constraints(state, loc, z, z_inv, res.clone())?;

                Boolean::create_unsafe(res)
            }
        };

        Ok(res)
    }

    /// Seals the value of a variable.
    ///
    /// As a [`FieldVar`] can represent an AST,
    /// it might not be a good idea to clone it and reuse it in several places.
    /// This is because the exact same reduction that will eventually happen on each clone
    /// will end up creating the same set of constraints multiple times in the circuit.
    ///
    /// It is useful to call on a variable that represents a long computation
    /// that hasn't been constrained yet (e.g. by an assert call, or a call to a custom gate),
    /// before using it further in the circuit.
    pub fn seal(&self, state: &mut RunState<F>, loc: Cow<'static, str>) -> SnarkyResult<Self> {
        match self.to_constant_and_terms() {
            (None, terms) if terms.len() == 1 && terms[0].0.is_one() => {
                Ok(FieldVar::Var(terms[0].1))
            }
            (Some(c), terms) if terms.is_empty() => Ok(FieldVar::Constant(c)),
            _ => {
                let y: FieldVar<F> = state.compute(loc.clone(), |env| env.read_var(self))?;
                // this call will reduce [self]
                self.assert_equals(state, loc, &y)?;

                Ok(y)
            }
        }
    }
}

//
// Traits
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

    fn check(&self, _cs: &mut RunState<F>, _loc: Cow<'static, str>) -> SnarkyResult<()> {
        // do nothing
        Ok(())
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
// Assertions
//

impl<F> FieldVar<F>
where
    F: PrimeField,
{
    pub fn assert_equals(
        &self,
        state: &mut RunState<F>,
        loc: Cow<'static, str>,
        other: &FieldVar<F>,
    ) -> SnarkyResult<()> {
        match (self, other) {
            (FieldVar::Constant(x), FieldVar::Constant(y)) => {
                if x == y {
                    Ok(())
                } else {
                    Err(
                        state.compilation_error(SnarkyCompilationError::ConstantAssertEquals(
                            x.to_string(),
                            y.to_string(),
                        )),
                    )
                }
            }
            (_, _) => state.add_constraint(
                Constraint::BasicSnarkyConstraint(BasicSnarkyConstraint::Equal(
                    self.clone(),
                    other.clone(),
                )),
                Some("assert equals".into()),
                loc,
            ),
        }
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
