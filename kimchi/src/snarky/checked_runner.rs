//! The circuit-generation and witness-generation logic.

use super::{api::Witness, constants::Constants};
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
    pub fn check_constraint(&self, env: &impl WitnessGeneration<F>) {
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
    BasicSnarkyConstraint(BasicSnarkyConstraint<CVar<F>>),

    /// Custom gates in kimchi.
    KimchiConstraint(KimchiConstraint<CVar<F>, F>),
}

/// The state used when compiling a circuit in snarky, or used in witness generation as well.
pub struct RunState<F>
where
    F: PrimeField,
{
    /// The constraint system used to build the circuit.
    /// If not set, the constraint system is not built.
    system: Option<SnarkyConstraintSystem<F>>,

    /// The public input of the circuit used in witness generation.
    // TODO: can we merge public_input and private_input?
    public_input: Vec<F>,

    // TODO: we could also just store `usize` here
    pub(crate) public_output: Vec<CVar<F>>,

    /// The private input of the circuit used in witness generation. Still not sure what that is, or why we care about this.
    private_input: Vec<F>,

    /// If set, the witness generation will check if the constraints are satisfied.
    /// This is useful to simulate running the circuit and return an error if an assertion fails.
    eval_constraints: bool,

    /// The number of public inputs.
    num_public_inputs: usize,

    /// A counter used to track variables (this includes public inputs) as they're being created.
    next_var: usize,

    /// Indication that we're running the witness generation.
    /// This does not necessarily mean that constraints are not created,
    /// as we can do both at the same time.
    // TODO: perhaps we should try to make the distinction between witness/constraint generation clearer
    has_witness: bool,

    /// Indication that we're running in prover mode.
    /// In this mode, we do not want to create constraints.
    // TODO: perhaps we should try to make the distinction between compile/runtime clearer
    pub(crate) as_prover: bool,
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
            if var_idx < self.num_public_inputs {
                self.public_input[var_idx]
            } else {
                self.private_input[var_idx - self.num_public_inputs]
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
    pub fn new<Curve: KimchiCurve<ScalarField = F>>(
        public_input_size: usize,
        public_output_size: usize,
    ) -> Self {
        // init
        let num_public_inputs = public_input_size + public_output_size;

        // create the CS
        let constants = Constants::new::<Curve>();
        let mut system = SnarkyConstraintSystem::create(constants);
        system.set_primary_input_size(num_public_inputs);

        // create the runner
        let mut sys = Self {
            system: Some(system),
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

    pub fn public_input<T: SnarkyType<F>>(&self) -> T {
        assert_eq!(
            T::SIZE_IN_FIELD_ELEMENTS,
            self.num_public_inputs - self.public_output.len()
        );

        let mut cvars = Vec::with_capacity(T::SIZE_IN_FIELD_ELEMENTS);
        for i in 0..T::SIZE_IN_FIELD_ELEMENTS {
            cvars.push(CVar::Var(i));
        }
        let aux = T::constraint_system_auxiliary();
        T::from_cvars_unsafe(cvars, aux)
    }

    /// Allocates a new var representing a private input.
    fn alloc_var(&mut self) -> CVar<F> {
        let v = self.next_var;
        self.next_var += 1;
        CVar::Var(v)
    }

    /// Stores a field element as an unconstrained private input.
    fn store_field_elt(&mut self, x: F) -> CVar<F> {
        let v = self.next_var;
        self.next_var += 1;
        self.private_input.push(x);
        CVar::Var(v)
    }

    pub(crate) fn public_output_values(&self, cvars: Vec<CVar<F>>) -> Vec<F> {
        let mut values = vec![];
        for cvar in cvars {
            match cvar {
                CVar::Var(idx) => {
                    dbg!(&self.private_input, self.num_public_inputs);
                    let val = self.private_input[idx - self.num_public_inputs];
                    values.push(val);
                }
                _ => panic!("public output must be a variable"),
            }
        }
        values
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
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
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

    /// Computes a closure with `as_prover` set to true.
    fn as_prover<T, FUNC>(&mut self, to_compute_value: FUNC) -> T::OutOfCircuit
    where
        T: SnarkyType<F>,
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        let old_as_prover = self.as_prover;
        self.as_prover = true;
        let value = to_compute_value(self);
        self.as_prover = old_as_prover;
        value
    }

    // TODO: make loc argument work
    fn compute_inner<T, FUNC>(&mut self, checked: bool, _loc: String, to_compute_value: FUNC) -> T
    where
        T: SnarkyType<F>,
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        // we're in witness generation mode
        if self.has_witness {
            // compute the value by running the closure
            // let old_as_prover = self.as_prover;
            // self.as_prover = true;
            // let value = to_compute_value(self);
            // self.as_prover = old_as_prover;
            let value = self.as_prover::<T, _>(to_compute_value);

            // convert the value into field elements
            let (fields, aux) = T::value_to_field_elements(&value);
            let mut field_vars = vec![];

            // convert each field element into a circuit var
            for field in fields {
                let v = if self.as_prover {
                    CVar::Constant(field)
                } else {
                    self.store_field_elt(field)
                };
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
                snarky_type.check(self);
            }

            // return the snarky type
            snarky_type
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
    // TODO: clean up all these add constraints functions
    pub fn add_constraints(&mut self, constraints: Vec<AnnotatedConstraint<F>>) {
        if self.as_prover {
            // Don't add constraints as the prover, or the constraint system won't match!
            return;
        }

        if self.eval_constraints {
            for constraint in &constraints {
                // TODO: return an error here instead of panicking
                constraint.check_constraint(self);
            }
        }

        self.add_constraints_inner(constraints);
    }

    pub fn add_constraint(&mut self, constraint: Constraint<F>, annotation: Option<&'static str>) {
        self.add_constraints(vec![AnnotatedConstraint {
            annotation,
            constraint,
        }])
    }

    fn add_constraints_inner(&mut self, constraints: Vec<AnnotatedConstraint<F>>) {
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
                self.assert_r1cs(Some("if_"), b.clone(), then_, else_);
                res
            }
        }
    }

    pub fn wire_public_output(&mut self, return_var: impl SnarkyType<F>) {
        let (return_cvars, _aux) = return_var.to_cvars();
        let public_output_cvars = self.public_output.clone();

        assert_eq!(return_cvars.len(), public_output_cvars.len());

        for (a, b) in return_cvars
            .into_iter()
            .zip(public_output_cvars.into_iter())
        {
            self.assert_eq(Some("wiring public output"), a, b);
        }
    }

    pub fn compile(&mut self) -> &[CircuitGate<F>] {
        if let Some(cs) = &mut self.system {
            cs.finalize_and_get_gates()
        } else {
            panic!("woot");
        }
    }

    pub fn generate_witness_init(&mut self, public_input: Vec<F>) {
        self.has_witness = true;
        self.public_input = public_input;
        self.next_var = self.num_public_inputs;
    }

    /// Returns the public output generated after running the circuit,
    /// and the witness of the execution trace.
    pub fn generate_witness(&mut self) -> Witness<F> {
        // TODO: asserting this is dumb.. what if there's no private input : D
        assert!(!self.private_input.is_empty());

        let system = self.system.as_mut().unwrap();

        let get_one = |var_idx| {
            if var_idx < self.num_public_inputs {
                self.public_input[var_idx]
            } else {
                self.private_input[var_idx - self.num_public_inputs]
            }
        };

        // compute witness
        let witness = system.compute_witness(get_one);

        // clear state (TODO: find better solution)
        self.public_input = vec![];
        self.next_var = self.num_public_inputs;

        // return public output and witness
        Witness(witness)
    }

    pub(crate) fn poseidon_params(&self) -> mina_poseidon::poseidon::ArithmeticSpongeParams<F> {
        self.system.as_ref().map(|sys| sys.sponge_params()).unwrap()
    }

    pub fn poseidon(&mut self, loc: String, preimage: (CVar<F>, CVar<F>)) -> (CVar<F>, CVar<F>) {
        super::poseidon::poseidon(loc, self, preimage)
    }
}
