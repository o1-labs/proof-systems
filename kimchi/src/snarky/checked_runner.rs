//! The circuit-generation and witness-generation logic.

use ark_ff::PrimeField;

use crate::{
    circuits::gate::CircuitGate,
    curve::KimchiCurve,
    loc,
    snarky::{
        boolean::Boolean,
        constraint_system::{BasicSnarkyConstraint, KimchiConstraint, SnarkyConstraintSystem},
        cvar::CVar,
        traits::SnarkyType,
    },
};

use super::constants::Constants;

/// A wrapper around [BasicSnarkyConstraint] and [KimchiConstraintSystem] that allows for an optional label (for debugging).
pub struct AnnotatedConstraint<F: PrimeField> {
    annotation: Option<&'static str>,
    constraint: Constraint<F>,
}

impl<F> AnnotatedConstraint<F>
where
    F: PrimeField,
{
    /// In witness generation, this checks if the constraint is satisfied by some witness values.
    pub fn check_constraint(&self, env: &impl WitnessGeneration<F>) {
        match &self.constraint {
            Constraint::BasicSnarkyConstraint(c) => c.check_constraint(env),
            Constraint::KimchiConstraint(c) => c.check_constraint(env),
        }
    }
}

/// An enum that wraps either a [BasicSnarkyConstraint] or a [KimchiConstraintSystem].
// TODO: we should get rid of this once basic constraint system is gone
pub enum Constraint<F: PrimeField> {
    /// Old R1CS-like constraints.
    BasicSnarkyConstraint(BasicSnarkyConstraint<CVar<F>>),

    /// Custom gates in kimchi.
    KimchiConstraint(KimchiConstraint<CVar<F>, F>),
}

/// The mode in which the [RunState] is running.
#[derive(Default, Clone, Copy)]
pub enum Mode {
    /// This will construct the kimchi gates for the circuit.
    #[default]
    CircuitGeneration,

    /// This will construct the execution trace (or witness) for the circuit.
    WitnessGeneration,
}

/// The state used when compiling a circuit in snarky, or used in witness generation as well.
#[derive(Default)]
pub struct RunState<F>
where
    F: PrimeField,
{
    /// The constraint system used to build the circuit.
    /// If not set, the constraint system is not built.
    system: Option<SnarkyConstraintSystem<F>>,

    /// The public input of the circuit used in witness generation.
    public_input: Vec<F>,

    /// The private input of the circuit used in witness generation. Still not sure what that is, or why we care about this.
    private_input: Vec<F>,

    /// If set, the witness generation will check if the constraints are satisfied.
    /// This is useful to simulate running the circuit and return an error if an assertion fails.
    eval_constraints: bool,

    /// The number of public inputs.
    num_public_inputs: usize,

    /// A counter used to track private inputs as they're being created.
    next_private_input: usize,

    /// Indication that we're running the witness generation (as opposed to the circuit creation).
    mode: Mode,
}

//
// witness generation
//

/// A witness generation environment.
/// This is passed to any closure in [RunState::compute] so that they can access the witness generation environment.
pub trait WitnessGeneration<F>
where
    F: PrimeField,
{
    /// Allows the caller to obtain the value behind a circuit variable.
    fn read_var(&self, var: &CVar<F>) -> F;
}

impl<F: PrimeField, G: WitnessGeneration<F>> WitnessGeneration<F> for &G {
    fn read_var(&self, var: &CVar<F>) -> F {
        G::read_var(*self, var)
    }
}

impl<F: PrimeField> WitnessGeneration<F> for &dyn WitnessGeneration<F> {
    fn read_var(&self, var: &CVar<F>) -> F {
        (**self).read_var(var)
    }
}

impl<F> WitnessGeneration<F> for RunState<F>
where
    F: PrimeField,
{
    fn read_var(&self, var: &CVar<F>) -> F {
        let get_one = |var_idx| {
            if var_idx <= self.num_public_inputs {
                // Run_state.Vector.get input (i - 1)
                self.public_input[var_idx - 1] // TODO: why -1?
            } else {
                //Run_state.Vector.get aux (i - num_inputs - 1)
                self.private_input[var_idx - self.num_public_inputs - 1] // TODO: why -1?
            }
        };

        var.eval(&get_one)
    }
}

//
// circuit generation
//

impl<F> RunState<F>
where
    F: PrimeField,
{
    // TODO: builder pattern?
    /// Creates a new [Self].
    pub fn new<Curve: KimchiCurve<ScalarField = F>>(num_public_inputs: usize) -> Self {
        let next_private_input = 1 + num_public_inputs;

        let constants = Constants::new::<Curve>();
        let mut system = SnarkyConstraintSystem::create(constants);
        system.set_primary_input_size(num_public_inputs);

        Self {
            system: Some(system),
            public_input: vec![],
            private_input: vec![],
            eval_constraints: false,
            num_public_inputs,
            next_private_input,
            mode: Mode::CircuitGeneration,
        }
    }

    /// Allocates a new var representing a private input.
    fn alloc_var(&mut self) -> CVar<F> {
        let v = self.next_private_input;
        self.next_private_input += 1;
        CVar::Var(v)
    }

    /// Stores a field element as an unconstrained private input.
    fn store_field_elt(&mut self, x: F) -> CVar<F> {
        let v = self.next_private_input;
        self.next_private_input += 1;
        self.private_input.push(x);
        CVar::Var(v)
    }

    /// Useful to debug. Similar to calling [Self::compute] on a unit type.
    pub fn debug() {
        todo!();
    }

    /// Creates a new non-deterministic variable associated to a value type ([SnarkyType]),
    /// and a closure that can compute it when in witness generation mode.
    pub fn compute<T, FUNC>(&mut self, loc: String, to_compute_value: FUNC) -> T
    where
        T: SnarkyType<F>,
        FUNC: Fn(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        self.compute_inner(true, loc, to_compute_value)
    }

    /// Same as [Self::compute] except that it does not attempt to constrain the value it computes.
    /// This is to be used internally only, when we know that the value cannot be malformed.
    pub(crate) fn compute_unsafe<T, FUNC>(&mut self, loc: String, to_compute_value: FUNC) -> T
    where
        T: SnarkyType<F>,
        FUNC: Fn(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        self.compute_inner(false, loc, to_compute_value)
    }

    // TODO: make loc argument work
    fn compute_inner<T, FUNC>(&mut self, checked: bool, _loc: String, to_compute_value: FUNC) -> T
    where
        T: SnarkyType<F>,
        FUNC: Fn(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        match self.mode {
            Mode::WitnessGeneration => {
                // compute the value by running the closure
                let value = to_compute_value(self);

                // convert the value into field elements
                let (fields, aux) = T::value_to_field_elements(&value);
                let mut field_vars = vec![];

                // convert each field element into a circuit var
                for field in fields {
                    let v = self.store_field_elt(field);
                    field_vars.push(v);
                }

                // parse them as a snarky type
                let snarky_type = T::from_cvars_unsafe(field_vars, aux);

                // constrain the conversion
                if checked {
                    snarky_type.check(self);
                }

                // return the snarky type
                snarky_type
            }
            Mode::CircuitGeneration => {
                // create enough variables to store the given type
                let mut cvars = vec![];
                for _ in 0..T::SIZE_IN_FIELD_ELEMENTS {
                    let v = self.alloc_var();
                    cvars.push(v);
                }

                // parse them as a snarky type
                let aux = T::constraint_system_auxiliary();
                let snarky_type = T::from_cvars_unsafe(cvars, aux);

                // constrain the created circuit variables
                if checked {
                    snarky_type.check(self);
                }

                // return the snarky type
                snarky_type
            }
        }
    }

    // TODO: get rid of this.
    /// Handles a list of [BasicSnarkyConstraint].
    pub fn assert_(
        &mut self,
        annotation: Option<&'static str>,
        basic_constraints: Vec<BasicSnarkyConstraint<CVar<F>>>,
    ) {
        let constraints: Vec<_> = basic_constraints
            .into_iter()
            .map(|c| AnnotatedConstraint {
                annotation,
                constraint: Constraint::BasicSnarkyConstraint(c),
            })
            .collect();

        self.add_constraints(constraints);
    }

    // TODO: get rid of this.
    /// Creates a constraint for `assert_eq!(a * b, c)`.
    pub fn assert_r1cs(
        &mut self,
        annotation: Option<&'static str>,
        a: CVar<F>,
        b: CVar<F>,
        c: CVar<F>,
    ) {
        let constraint = BasicSnarkyConstraint::R1CS(a, b, c);
        self.assert_(annotation, vec![constraint]);
    }

    // TODO: get rid of this
    /// Creates a constraint for `assert_eq!(x, y)`;
    pub fn assert_eq(&mut self, annotation: Option<&'static str>, x: CVar<F>, y: CVar<F>) {
        let constraint = BasicSnarkyConstraint::Equal(x, y);
        self.assert_(annotation, vec![constraint]);
    }
    /// Adds a list of [AnnotatedConstraint]s to the circuit.
    pub fn add_constraints(&mut self, constraints: Vec<AnnotatedConstraint<F>>) {
        match self.mode {
            Mode::WitnessGeneration => {
                if self.eval_constraints {
                    for constraint in &constraints {
                        constraint.check_constraint(self);
                    }
                }
            }
            Mode::CircuitGeneration => {
                self.add_constraint_inner(constraints);
            }
        }
    }

    fn add_constraint_inner(&mut self, constraints: Vec<AnnotatedConstraint<F>>) {
        let cs = match &mut self.system {
            Some(cs) => cs,
            None => return, // TODO: why silent fail?
        };

        for constraint in constraints {
            let _label = constraint.annotation.unwrap_or("<unknown>");

            match constraint.constraint {
                Constraint::BasicSnarkyConstraint(c) => {
                    cs.add_basic_snarky_constraint(c);
                }
                Constraint::KimchiConstraint(c) => {
                    cs.add_constraint(c);
                }
            }
        }
    }

    /// Adds a constraint that returns `then_` if `b` is `true`, `else_` otherwise.
    /// Equivalent to `if b { then_ } else { else_ }`.
    pub fn if_(&mut self, b: Boolean<F>, then_: CVar<F>, else_: CVar<F>) -> CVar<F> {
        // r = e + b (t - e)
        // r - e = b (t - e)
        let cvars = b.to_cvars().0;
        let b = &cvars[0];
        if let CVar::Constant(b) = b {
            if b.is_one() {
                return then_;
            } else {
                return else_;
            }
        }

        match (&then_, &else_) {
            (CVar::Constant(t), CVar::Constant(e)) => {
                let t_times_b = b.scale(*t);
                let one_minus_b = CVar::Constant(F::one()) - b;
                t_times_b + &one_minus_b.scale(*e)
            }
            _ => {
                let b_clone = b.clone();
                let then_clone = then_.clone();
                let else_clone = else_.clone();
                let res: CVar<F> = self.compute(loc!(), move |env| {
                    let b = env.read_var(&b_clone);
                    let res_var = if b == F::one() {
                        &then_clone
                    } else {
                        &else_clone
                    };
                    let res: F = res_var.read(env);
                    res
                });
                let then_ = &then_ - &else_;
                let else_ = &res - &else_;
                // TODO: annotation?
                self.assert_r1cs(None, b.clone(), then_, else_);
                res
            }
        }
    }

    pub fn compile(&mut self) -> &[CircuitGate<F>] {
        if let Some(cs) = &mut self.system {
            cs.finalize_and_get_gates()
        } else {
            panic!("woot");
        }
    }

    pub fn generate_witness(&mut self, public_input: Vec<F>) {
        self.mode = Mode::WitnessGeneration;
        self.public_input = public_input;
        // TODO: this is probably really wrong
    }

    pub fn generate_witness_end(&mut self) -> Vec<Vec<F>> {
        // TODO: asserting this is dumb.. what if there's no private input : D
        assert!(!self.private_input.is_empty());
        if let Some(cs) = &mut self.system {
            let get_one = |var_idx| {
                if var_idx <= self.num_public_inputs {
                    // Run_state.Vector.get input (i - 1)
                    self.public_input[var_idx - 1] // TODO: why -1?
                } else {
                    //Run_state.Vector.get aux (i - num_inputs - 1)
                    self.private_input[var_idx - self.num_public_inputs - 1] // TODO: why -1?
                }
            };

            cs.compute_witness(get_one)
        } else {
            panic!("woot");
        }
    }
}
