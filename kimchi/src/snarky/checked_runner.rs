//! The circuit-generation and witness-generation logic.

use super::{
    api::Witness,
    constants::Constants,
    errors::{SnarkyError, SnarkyResult, SnarkyRuntimeResult},
    poseidon::poseidon,
};
use crate::{
    circuits::gate::CircuitGate,
    curve::KimchiCurve,
    loc,
    snarky::{
        boolean::Boolean,
        constraint_system::{BasicSnarkyConstraint, KimchiConstraint, SnarkyConstraintSystem},
        cvar::FieldVar,
        errors::SnarkyRuntimeError,
        traits::SnarkyType,
    },
};
use ark_ff::PrimeField;

/// A wrapper around [BasicSnarkyConstraint] and [KimchiConstraintSystem] that allows for an optional label (for debugging).
#[derive(Debug)]
pub struct AnnotatedConstraint<F: PrimeField> {
    annotation: Option<&'static str>,
    constraint: Constraint<F>,
}

impl<F> AnnotatedConstraint<F>
where
    F: PrimeField,
{
    /// In witness generation, this checks if the constraint is satisfied by some witness values.
    pub fn check_constraint(&self, env: &impl WitnessGeneration<F>) -> SnarkyRuntimeResult<()> {
        match &self.constraint {
            Constraint::BasicSnarkyConstraint(c) => c.check_constraint(env),
            Constraint::KimchiConstraint(c) => c.check_constraint(env),
        }
    }
}

/// An enum that wraps either a [BasicSnarkyConstraint] or a [KimchiConstraintSystem].
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
    num_public_inputs: usize,

    /// A counter used to track variables (this includes public inputs) as they're being created.
    pub next_var: usize,

    /// Indication that we're running the witness generation.
    /// This does not necessarily mean that constraints are not created,
    /// as we can do both at the same time.
    // TODO: perhaps we should try to make the distinction between witness/constraint generation clearer
    pub has_witness: bool,

    /// Indication that we're running in prover mode.
    /// In this mode, we do not want to create constraints.
    // TODO: I think we should be able to safely remove this as we don't use this in Rust
    pub as_prover: bool,
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
}

impl<F: PrimeField, G: WitnessGeneration<F>> WitnessGeneration<F> for &G {
    fn read_var(&self, var: &FieldVar<F>) -> F {
        G::read_var(*self, var)
    }
}

impl<F: PrimeField> WitnessGeneration<F> for &dyn WitnessGeneration<F> {
    fn read_var(&self, var: &FieldVar<F>) -> F {
        (**self).read_var(var)
    }
}

impl<F> WitnessGeneration<F> for RunState<F>
where
    F: PrimeField,
{
    fn read_var(&self, var: &FieldVar<F>) -> F {
        var.eval(self)
    }
}

//
// Sponge
//

pub struct DuplexState<F>
where
    F: PrimeField,
{
    rev_queue: Vec<FieldVar<F>>,
    absorbing: bool,
    squeezed: Option<FieldVar<F>>,
    state: [FieldVar<F>; 3],
}

const RATE_SIZE: usize = 2;

impl<F> DuplexState<F>
where
    F: PrimeField,
{
    /// Creates a new sponge.
    pub fn new() -> DuplexState<F> {
        let state = [FieldVar::zero(), FieldVar::zero(), FieldVar::zero()];
        DuplexState {
            rev_queue: vec![],
            absorbing: true,
            squeezed: None,
            state,
        }
    }

    /// Absorb.
    pub fn absorb(&mut self, sys: &mut RunState<F>, inputs: &[FieldVar<F>]) {
        // no need to permute to switch to absorbing
        if !self.absorbing {
            assert!(self.rev_queue.is_empty());
            self.squeezed = None;
            self.absorbing = true;
        }

        // absorb
        for input in inputs {
            // we only permute when we try to absorb too much (we lazy)
            if self.rev_queue.len() == RATE_SIZE {
                let left = self.rev_queue.pop().unwrap();
                let right = self.rev_queue.pop().unwrap();
                self.state[0] = &self.state[0] + left;
                self.state[1] = &self.state[1] + right;
                self.permute(sys);
            }

            self.rev_queue.insert(0, input.clone());
        }
    }

    /// Permute. You should most likely not use this function directly,
    /// and use [Self::absorb] and [Self::squeeze] instead.
    fn permute(&mut self, sys: &mut RunState<F>) -> (FieldVar<F>, FieldVar<F>) {
        let left = self.state[0].clone();
        let right = self.state[1].clone();
        sys.poseidon("does poseidon really need a loc?", (left, right))
    }

    /// Squeeze.
    pub fn squeeze(&mut self, sys: &mut RunState<F>) -> FieldVar<F> {
        // if we're switching to squeezing, don't forget about the queue
        if self.absorbing {
            assert!(self.squeezed.is_none());
            if let Some(left) = self.rev_queue.pop() {
                self.state[0] = &self.state[0] + left;
            }
            if let Some(right) = self.rev_queue.pop() {
                self.state[1] = &self.state[1] + right;
            }
            self.absorbing = false;
        }

        // if we still have some left over, release that
        if let Some(squeezed) = self.squeezed.take() {
            return squeezed;
        }

        // otherwise permute and squeeze
        let (left, right) = self.permute(sys);

        // cache the right, release the left
        self.squeezed = Some(right);
        left
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
            eval_constraints: false,
            num_public_inputs,
            next_var: 0,
            has_witness: false,
            as_prover: false,
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

    /// Useful to debug. Similar to calling [Self::compute] on a unit type.
    pub fn debug() {
        todo!();
    }

    /// Creates a new non-deterministic variable associated to a value type ([SnarkyType]),
    /// and a closure that can compute it when in witness generation mode.
    pub fn compute<T, FUNC>(&mut self, loc: &str, to_compute_value: FUNC) -> SnarkyResult<T>
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
        loc: &str,
        to_compute_value: FUNC,
    ) -> SnarkyResult<T>
    where
        T: SnarkyType<F>,
        FUNC: Fn(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        self.compute_inner(false, loc, to_compute_value)
    }

    // TODO: make loc argument work
    fn compute_inner<T, FUNC>(
        &mut self,
        checked: bool,
        _loc: &str,
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
                snarky_type.check(self)?;
            }

            // return the snarky type
            Ok(snarky_type)
        }
        /* we're in constraint generation mode */
        else {
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
                snarky_type.check(self)?;
            }

            // return the snarky type
            Ok(snarky_type)
        }
    }

    // TODO: get rid of this.
    /// Handles a list of [BasicSnarkyConstraint].
    pub fn assert_(
        &mut self,
        annotation: Option<&'static str>,
        basic_constraints: Vec<BasicSnarkyConstraint<FieldVar<F>>>,
    ) -> SnarkyResult<()> {
        let constraints: Vec<_> = basic_constraints
            .into_iter()
            .map(|c| AnnotatedConstraint {
                annotation,
                constraint: Constraint::BasicSnarkyConstraint(c),
            })
            .collect();

        self.add_constraints(constraints)
    }

    // TODO: get rid of this.
    /// Creates a constraint for `assert_eq!(a * b, c)`.
    pub fn assert_r1cs(
        &mut self,
        annotation: Option<&'static str>,
        a: FieldVar<F>,
        b: FieldVar<F>,
        c: FieldVar<F>,
    ) -> SnarkyResult<()> {
        let constraint = BasicSnarkyConstraint::R1CS(a, b, c);
        self.assert_(annotation, vec![constraint])
    }

    // TODO: get rid of this
    /// Creates a constraint for `assert_eq!(x, y)`;
    pub fn assert_eq(
        &mut self,
        annotation: Option<&'static str>,
        x: FieldVar<F>,
        y: FieldVar<F>,
    ) -> SnarkyResult<()> {
        let constraint = BasicSnarkyConstraint::Equal(x, y);
        self.assert_(annotation, vec![constraint])
    }

    /// Adds a list of [AnnotatedConstraint]s to the circuit.
    // TODO: clean up all these add constraints functions
    pub fn add_constraints(
        &mut self,
        constraints: Vec<AnnotatedConstraint<F>>,
    ) -> SnarkyResult<()> {
        // We can't evaluate the constraints if we are not computing over a value.
        if self.eval_constraints && self.has_witness {
            for constraint in &constraints {
                constraint
                    .check_constraint(self)
                    .map_err(SnarkyError::RuntimeError)?;
            }
        }

        self.add_constraints_inner(constraints);

        Ok(())
    }

    pub fn add_constraint(
        &mut self,
        constraint: Constraint<F>,
        annotation: Option<&'static str>,
    ) -> SnarkyResult<()> {
        self.add_constraints(vec![AnnotatedConstraint {
            annotation,
            constraint,
        }])
    }

    fn add_constraints_inner(&mut self, constraints: Vec<AnnotatedConstraint<F>>) {
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
        if self.has_witness {
            return;
        }

        // TODO: we should have a mode "don't create constraints" instead of having an option here
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
    pub fn if_(
        &mut self,
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
                let res: FieldVar<F> = self.compute(&loc!(), move |env| {
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
                self.assert_r1cs(Some("if_"), b.clone(), then_, else_)?;

                Ok(res)
            }
        }
    }

    pub(crate) fn wire_public_output(
        &mut self,
        return_var: impl SnarkyType<F>,
    ) -> SnarkyResult<()> {
        // obtain cvars for the returned vars
        let (return_cvars, _aux) = return_var.to_cvars();

        // obtain the vars involved in the public output part of the public input
        let public_output_cvars = self.public_output.clone();
        if return_cvars.len() != public_output_cvars.len() {
            return Err(SnarkyError::RuntimeError(
                SnarkyRuntimeError::CircuitReturnVar(return_cvars.len(), public_output_cvars.len()),
            ));
        }

        // wire these to the public output part of the public input
        // note: this will reduce the cvars contained in the output vars
        for (a, b) in return_cvars
            .into_iter()
            .zip(public_output_cvars.into_iter())
        {
            self.assert_eq(Some("wiring public output"), a, b)?;
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

    #[cfg(feature = "ocaml_types")]
    pub fn get_private_inputs(&self) -> Vec<F> {
        self.private_input.clone()
    }

    pub fn generate_witness_init(&mut self, mut public_input: Vec<F>) -> SnarkyResult<()> {
        let obtained = public_input.len();
        let expected = self.num_public_inputs - self.public_output.len();
        if expected != obtained {
            return Err(SnarkyError::RuntimeError(
                SnarkyRuntimeError::PubInputMismatch(obtained, expected),
            ));
        }

        // pad with zeros for the public output part
        public_input.extend(std::iter::repeat(F::zero()).take(self.public_output.len()));

        // re-initialize `next_var` (which will grow every time we compile or generate a witness)
        self.next_var = self.num_public_inputs;

        // set the mode to "witness generation"
        self.has_witness = true;

        // set the public inputs
        self.public_input = public_input;

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
        loc: &str,
        preimage: (FieldVar<F>, FieldVar<F>),
    ) -> (FieldVar<F>, FieldVar<F>) {
        poseidon(self, loc, preimage)
    }
}
