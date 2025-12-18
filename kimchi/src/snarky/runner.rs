//! The circuit-generation and witness-generation logic.

use std::borrow::Cow;

use super::{
    api::Witness,
    constants::Constants,
    errors::{
        RealSnarkyError, SnarkyCompilationError, SnarkyError, SnarkyResult, SnarkyRuntimeResult,
    },
    poseidon::poseidon,
    range_checks::range_check,
};
use crate::{
    circuits::gate::CircuitGate,
    curve::KimchiCurve,
    snarky::{
        boolean::Boolean,
        constraint_system::{BasicSnarkyConstraint, KimchiConstraint, SnarkyConstraintSystem},
        cvar::FieldVar,
        errors::SnarkyRuntimeError,
        snarky_type::SnarkyType,
    },
};
use ark_ff::PrimeField;
use o1_utils::repeat_n;

impl<F> Constraint<F>
where
    F: PrimeField,
{
    /// In witness generation, this checks if the constraint is satisfied by some witness values.
    pub fn check_constraint(&self, env: &impl WitnessGeneration<F>) -> SnarkyRuntimeResult<()> {
        match self {
            Constraint::BasicSnarkyConstraint(c) => c.check_constraint(env),
            Constraint::KimchiConstraint(c) => c.check_constraint(env),
        }
    }
}

/// An enum that wraps either a [`BasicSnarkyConstraint`] or a \[`KimchiConstraintSystem`\].
// TODO: we should get rid of this once basic constraint system is gone
#[derive(Debug)]
pub enum Constraint<F: PrimeField> {
    /// Old R1CS-like constraints.
    BasicSnarkyConstraint(BasicSnarkyConstraint<FieldVar<F>>),

    /// Custom gates in kimchi.
    KimchiConstraint(KimchiConstraint<FieldVar<F>, F>),
}

/// The state used when compiling a circuit in snarky, or used in witness generation as well.
#[derive(Debug)]
pub struct RunState<F>
where
    F: PrimeField,
{
    /// The constraint system used to build the circuit.
    /// If not set, the constraint system is not built.
    pub system: Option<SnarkyConstraintSystem<F>>,

    /// The public input of the circuit used in witness generation.
    // TODO: can we merge public_input and private_input?
    public_input: Vec<F>,

    // TODO: we could also just store `usize` here
    pub(crate) public_output: Vec<FieldVar<F>>,

    /// The private input of the circuit used in witness generation. Still not sure what that is, or why we care about this.
    private_input: Vec<F>,

    /// If set, the witness generation will check if the constraints are satisfied.
    /// This is useful to simulate running the circuit and return an error if an assertion fails.
    pub eval_constraints: bool,

    /// The size of the public input part. This contains the public output as well.
    // TODO: maybe remove the public output part here? This will affect OCaml-side though.
    pub num_public_inputs: usize,

    /// A counter used to track variables (this includes public inputs) as they're being created.
    pub next_var: usize,

    /// Indication that we're running the witness generation.
    /// This does not necessarily mean that constraints are not created,
    /// as we can do both at the same time.
    // TODO: perhaps we should try to make the distinction between witness/constraint generation clearer
    pub has_witness: bool,

    /// Indication that we're running in prover mode.
    /// In this mode, we do not want to create constraints.
    // TODO: I think we should be able to safely remove this as we don't use this in Rust. Check with snarkyJS if they need this here though.
    pub as_prover: bool,

    /// A stack of labels, to get better errors.
    labels_stack: Vec<Cow<'static, str>>,

    /// This does not count exactly the number of constraints,
    /// but rather the number of times we call [RunState::add_constraint].
    constraints_counter: usize,

    /// A map from a constraint index to a source location
    /// (usually a file name and line number).
    constraints_locations: Vec<Cow<'static, str>>,
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
    fn read_var(&self, var: &FieldVar<F>) -> F;

    fn constraints_counter(&self) -> usize;
}

impl<F: PrimeField, G: WitnessGeneration<F>> WitnessGeneration<F> for &G {
    fn read_var(&self, var: &FieldVar<F>) -> F {
        G::read_var(*self, var)
    }

    fn constraints_counter(&self) -> usize {
        G::constraints_counter(*self)
    }
}

impl<F: PrimeField> WitnessGeneration<F> for &dyn WitnessGeneration<F> {
    fn read_var(&self, var: &FieldVar<F>) -> F {
        (**self).read_var(var)
    }

    fn constraints_counter(&self) -> usize {
        (**self).constraints_counter()
    }
}

impl<F> WitnessGeneration<F> for RunState<F>
where
    F: PrimeField,
{
    fn read_var(&self, var: &FieldVar<F>) -> F {
        var.eval(self)
    }

    fn constraints_counter(&self) -> usize {
        self.constraints_counter
    }
}

//
// circuit generation
//

impl<F> RunState<F>
where
    F: PrimeField,
{
    /// Creates a new [`Self`] based on the size of the public input,
    /// and the size of the public output.
    /// If `with_system` is set it will create a [SnarkyConstraintSystem] in
    /// order to compile a new circuit.
    pub fn new<Curve: KimchiCurve<ScalarField = F>>(
        public_input_size: usize,
        public_output_size: usize,
        with_system: bool,
    ) -> Self {
        // init
        let num_public_inputs = public_input_size + public_output_size;

        // create the CS
        let constants = Constants::new::<Curve>();
        let system = if with_system {
            let mut system = SnarkyConstraintSystem::create(constants);
            system.set_primary_input_size(num_public_inputs);
            Some(system)
        } else {
            None
        };

        // create the runner
        let mut sys = Self {
            system,
            public_input: Vec::with_capacity(num_public_inputs),
            public_output: Vec::with_capacity(public_output_size),
            private_input: vec![],
            eval_constraints: true,
            num_public_inputs,
            next_var: 0,
            has_witness: false,
            as_prover: false,
            labels_stack: vec![],
            constraints_counter: 0,
            constraints_locations: vec![],
        };

        // allocate the public inputs
        for _ in 0..public_input_size {
            sys.alloc_var();
        }

        // allocate the public output and store it
        for _ in 0..public_output_size {
            let cvar = sys.alloc_var();
            sys.public_output.push(cvar);
        }

        //
        sys
    }

    /// Used internaly to evaluate variables.
    /// Can panic if used with a wrong index.
    pub fn read_var_idx(&self, idx: usize) -> F {
        if idx < self.num_public_inputs {
            self.public_input[idx]
        } else {
            self.private_input[idx - self.num_public_inputs]
        }
    }

    /// Returns the public input snarky variable.
    // TODO: perhaps this should be renamed `compile_circuit` and encapsulate more logic (since this is only used to compile a given circuit)
    pub fn public_input<T: SnarkyType<F>>(&self) -> T {
        assert_eq!(
            T::SIZE_IN_FIELD_ELEMENTS,
            self.num_public_inputs - self.public_output.len()
        );

        let mut cvars = Vec::with_capacity(T::SIZE_IN_FIELD_ELEMENTS);
        for i in 0..T::SIZE_IN_FIELD_ELEMENTS {
            cvars.push(FieldVar::Var(i));
        }
        let aux = T::constraint_system_auxiliary();
        T::from_cvars_unsafe(cvars, aux)
    }

    /// Allocates a new var representing a private input.
    pub fn alloc_var(&mut self) -> FieldVar<F> {
        let v = self.next_var;
        self.next_var += 1;
        FieldVar::Var(v)
    }

    /// Stores a field element as an unconstrained private input.
    pub fn store_field_elt(&mut self, x: F) -> FieldVar<F> {
        let v = self.next_var;
        self.next_var += 1;
        self.private_input.push(x);
        FieldVar::Var(v)
    }

    /// Creates a new non-deterministic variable associated to a value type ([SnarkyType]),
    /// and a closure that can compute it when in witness generation mode.
    pub fn compute<T, FUNC>(
        &mut self,
        loc: Cow<'static, str>,
        to_compute_value: FUNC,
    ) -> SnarkyResult<T>
    where
        T: SnarkyType<F>,
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        self.compute_inner(true, loc, to_compute_value)
    }

    /// Same as [Self::compute] except that it does not attempt to constrain the value it computes.
    /// This is to be used internally only, when we know that the value cannot be malformed.
    pub(crate) fn compute_unsafe<T, FUNC>(
        &mut self,
        loc: Cow<'static, str>,
        to_compute_value: FUNC,
    ) -> SnarkyResult<T>
    where
        T: SnarkyType<F>,
        FUNC: Fn(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        self.compute_inner(false, loc, to_compute_value)
    }

    /// The logic called by both [Self::compute] and [Self::compute_unsafe].
    fn compute_inner<T, FUNC>(
        &mut self,
        checked: bool,
        loc: Cow<'static, str>,
        to_compute_value: FUNC,
    ) -> SnarkyResult<T>
    where
        T: SnarkyType<F>,
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        // we're in witness generation mode
        if self.has_witness {
            // compute the value by running the closure
            let value: T::OutOfCircuit = to_compute_value(self);

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
                snarky_type.check(self, loc)?;
            }

            // return the snarky type
            Ok(snarky_type)
        }
        /* we're in constraint generation mode */
        else {
            // create enough variables to store the given type
            let mut cvars = vec![];
            for _ in 0..T::SIZE_IN_FIELD_ELEMENTS {
                // TODO: rename to alloc_cvar
                let v = self.alloc_var();
                cvars.push(v);
            }

            // parse them as a snarky type
            let aux = T::constraint_system_auxiliary();
            let snarky_type = T::from_cvars_unsafe(cvars, aux);

            // constrain the created circuit variables
            if checked {
                snarky_type.check(self, loc)?;
            }

            // return the snarky type
            Ok(snarky_type)
        }
    }

    // TODO: get rid of this.
    /// Creates a constraint for `assert_eq!(a * b, c)`.
    pub fn assert_r1cs(
        &mut self,
        label: Option<Cow<'static, str>>,
        loc: Cow<'static, str>,
        a: FieldVar<F>,
        b: FieldVar<F>,
        c: FieldVar<F>,
    ) -> SnarkyResult<()> {
        let constraint = BasicSnarkyConstraint::R1CS(a, b, c);
        self.add_constraint(Constraint::BasicSnarkyConstraint(constraint), label, loc)
    }

    // TODO: get rid of this
    /// Creates a constraint for `assert_eq!(x, y)`;
    pub fn assert_eq(
        &mut self,
        label: Option<Cow<'static, str>>,
        loc: Cow<'static, str>,
        x: FieldVar<F>,
        y: FieldVar<F>,
    ) -> SnarkyResult<()> {
        let constraint = BasicSnarkyConstraint::Equal(x, y);
        self.add_constraint(Constraint::BasicSnarkyConstraint(constraint), label, loc)
    }

    /// Adds a list of [`Constraint`] to the circuit.
    // TODO: clean up all these add constraints functions
    // TODO: do I really need to pass a vec?
    pub fn add_constraint(
        &mut self,
        constraint: Constraint<F>,
        label: Option<Cow<'static, str>>,
        // TODO: we don't need to pass that through all the calls down the stack, we can just save it at this point (and the latest loc in the state is the one that threw)
        loc: Cow<'static, str>,
    ) -> SnarkyResult<()> {
        self.with_label(label, |env| {
            // increment the constraint counter
            env.constraints_counter += 1;

            // TODO:
            // [START_TODO]
            // my understanding is that this should work with the OCaml side,
            // as `generate_witness_conv` on the OCaml side will have an empty constraint_system at this point which means constraints can't be created (see next line)
            // instead, I just ensure that when we're in witness generation we don't create constraints
            // I don't think we ever do both at the same time on the OCaml side side anyway.
            // Note: if we want to address the TODO below, I think we should instead do this:
            // have an enum: 1) compile 2) witness generation 3) both
            // and have the both enum variant be used from an API that does both
            // [END_TODO]
            env.constraints_locations.push(loc.clone());

            // We check the constraint
            // TODO: this is checked at the front end level, perhaps we should check at the constraint system / backend level so that we can tell exactly what row is messed up? (for internal debugging that would really help)
            if env.has_witness && env.eval_constraints {
                constraint
                    .check_constraint(env)
                    .map_err(|e| env.runtime_error(*e))?;
            }

            if !env.has_witness {
                // TODO: we should have a mode "don't create constraints" instead of having an option here
                let cs = match &mut env.system {
                    Some(cs) => cs,
                    None => return Ok(()),
                };

                match constraint {
                    Constraint::BasicSnarkyConstraint(c) => {
                        cs.add_basic_snarky_constraint(&env.labels_stack, &loc, c);
                    }
                    Constraint::KimchiConstraint(c) => {
                        cs.add_constraint(&env.labels_stack, &loc, c);
                    }
                }
            }

            Ok(())
        })
    }

    /// Adds a constraint that returns `then_` if `b` is `true`, `else_` otherwise.
    /// Equivalent to `if b { then_ } else { else_ }`.
    // TODO: move this out
    pub fn if_(
        &mut self,
        loc: Cow<'static, str>,
        b: Boolean<F>,
        then_: FieldVar<F>,
        else_: FieldVar<F>,
    ) -> SnarkyResult<FieldVar<F>> {
        // r = e + b (t - e)
        // r - e = b (t - e)
        let cvars = b.to_cvars().0;
        let b = &cvars[0];
        if let FieldVar::Constant(b) = b {
            if b.is_one() {
                return Ok(then_);
            } else {
                return Ok(else_);
            }
        }

        match (&then_, &else_) {
            (FieldVar::Constant(t), FieldVar::Constant(e)) => {
                let t_times_b = b.scale(*t);
                let one_minus_b = FieldVar::Constant(F::one()) - b;
                Ok(t_times_b + &one_minus_b.scale(*e))
            }
            _ => {
                let b_clone = b.clone();
                let then_clone = then_.clone();
                let else_clone = else_.clone();
                let res: FieldVar<F> = self.compute(loc.clone(), move |env| {
                    let b = env.read_var(&b_clone);
                    let res_var = if b == F::one() {
                        &then_clone
                    } else {
                        &else_clone
                    };
                    let res: F = res_var.read(env);
                    res
                })?;
                let then_ = &then_ - &else_;
                let else_ = &res - &else_;
                // TODO: annotation?
                self.assert_r1cs(Some("if_".into()), loc, b.clone(), then_, else_)?;

                Ok(res)
            }
        }
    }

    /// Wires the given snarky variable to the public output part of the public input.
    pub(crate) fn wire_public_output(
        &mut self,
        return_var: impl SnarkyType<F>,
    ) -> SnarkyResult<()> {
        // obtain cvars for the returned vars
        let (return_cvars, _aux) = return_var.to_cvars();

        // obtain the vars involved in the public output part of the public input
        let public_output_cvars = self.public_output.clone();
        if return_cvars.len() != public_output_cvars.len() {
            return Err(self.runtime_error(SnarkyRuntimeError::CircuitReturnVar(
                return_cvars.len(),
                public_output_cvars.len(),
            )));
        }

        // wire these to the public output part of the public input
        // note: this will reduce the cvars contained in the output vars
        for (a, b) in return_cvars
            .into_iter()
            .zip(public_output_cvars.into_iter())
        {
            self.assert_eq(
                Some("wiring public output".into()),
                "this should never error".into(),
                a,
                b,
            )?;
        }

        Ok(())
    }

    /// Finalizes the public output using the actual variables returned by the circuit.
    pub(crate) fn wire_output_and_compile(
        &mut self,
        return_var: impl SnarkyType<F>,
    ) -> SnarkyResult<&[CircuitGate<F>]> {
        // wire output
        self.wire_public_output(return_var)?;

        // compile
        if let Some(cs) = &mut self.system {
            Ok(cs.finalize_and_get_gates())
        } else {
            // TODO: do we really want to panic here?
            panic!("woot");
        }
    }

    /// Getter for the OCaml side.
    #[cfg(feature = "ocaml_types")]
    pub fn get_private_inputs(&self) -> Vec<F> {
        self.private_input.clone()
    }

    /// This adds a label in the stack of labels.
    /// Every error from now one will contain this label,
    /// until the label is popped (via [Self::pop_label]).
    pub fn add_label(&mut self, label: Cow<'static, str>) {
        self.labels_stack.push(label);
    }

    /// This removes a label from any error that could come up from now on.
    /// Normally used shortly after [Self::add_label].
    pub fn pop_label(&mut self) {
        self.labels_stack.pop();
    }

    /// A wrapper around code that needs to be labeled
    /// (for better errors).
    pub fn with_label<FUNC, T>(&mut self, label: Option<Cow<'static, str>>, closure: FUNC) -> T
    where
        FUNC: FnOnce(&mut Self) -> T,
    {
        let need_to_pop = label.is_some();

        if let Some(label) = label {
            self.add_label(label);
        }

        let res = closure(self);

        if need_to_pop {
            self.pop_label();
        }

        res
    }

    /// Creates an [RealSnarkyError] using the current context.
    pub fn error(&self, error: SnarkyError) -> RealSnarkyError {
        let loc = if self.constraints_counter == 0 {
            "error during initialization".into()
        } else {
            self.constraints_locations[self.constraints_counter - 1].clone()
        };
        RealSnarkyError::new_with_ctx(error, loc, self.labels_stack.clone())
    }

    /// Creates a runtime error.
    pub fn runtime_error(&self, error: SnarkyRuntimeError) -> Box<RealSnarkyError> {
        Box::new(self.error(SnarkyError::RuntimeError(error)))
    }

    /// Crates a compilation error.
    pub fn compilation_error(&self, error: SnarkyCompilationError) -> Box<RealSnarkyError> {
        Box::new(self.error(SnarkyError::CompilationError(error)))
    }

    pub fn generate_witness_init(&mut self, mut public_input: Vec<F>) -> SnarkyResult<()> {
        // check that the given public_input is of the correct length
        // (not including the public output)
        let obtained = public_input.len();
        let expected = self.num_public_inputs - self.public_output.len();
        if expected != obtained {
            return Err(
                self.runtime_error(SnarkyRuntimeError::PubInputMismatch(obtained, expected))
            );
        }

        // pad with zeros for the public output part
        public_input.extend(repeat_n(F::zero(), self.public_output.len()));

        // re-initialize `next_var` (which will grow every time we compile or generate a witness)
        self.next_var = self.num_public_inputs;

        // set the mode to "witness generation"
        self.has_witness = true;

        // set the public inputs
        self.public_input = public_input;

        // reset the private inputs
        self.private_input = Vec::with_capacity(self.private_input.len());

        // reset the constraint counter for better debugging
        self.constraints_counter = 0;

        // reset the constraints' locations
        // we have to do this to imitate what the OCaml side does
        // (the OCaml side always starts with a fresh state)
        self.constraints_locations = Vec::with_capacity(self.constraints_locations.len());

        Ok(())
    }

    /// Returns the public output generated after running the circuit,
    /// and the witness of the execution trace.
    pub fn generate_witness(&mut self) -> Witness<F> {
        // TODO: asserting this is dumb.. what if there's no private input : D
        assert!(!self.private_input.is_empty());

        // TODO: do we really want to panic here?
        let system = self.system.as_mut().unwrap();

        let get_one = |var_idx| {
            if var_idx < self.num_public_inputs {
                self.public_input[var_idx]
            } else {
                self.private_input[var_idx - self.num_public_inputs]
            }
        };

        // compute witness
        // TODO: can we avoid passing a closure here? a reference to a Inputs struct would be better perhaps.
        let witness = system.compute_witness(get_one);

        // clear state (TODO: find better solution)
        self.public_input = vec![];
        self.next_var = self.num_public_inputs;

        // return public output and witness
        Witness(witness)
    }

    pub(crate) fn poseidon_params(&self) -> mina_poseidon::poseidon::ArithmeticSpongeParams<F> {
        // TODO: do we really want to panic here?
        self.system.as_ref().map(|sys| sys.sponge_params()).unwrap()
    }

    pub fn poseidon(
        &mut self,
        loc: Cow<'static, str>,
        preimage: (FieldVar<F>, FieldVar<F>),
    ) -> (FieldVar<F>, FieldVar<F>) {
        poseidon(self, loc, preimage)
    }
    ///constrains the 3 provided values to fit in 88 bits
    pub fn range_check(
        &mut self,
        loc: Cow<'static, str>,
        v0: FieldVar<F>,
        v1: FieldVar<F>,
        v2: FieldVar<F>,
    ) -> SnarkyResult<()> {
        range_check(self, loc, v0, v1, v2)
    }
}
