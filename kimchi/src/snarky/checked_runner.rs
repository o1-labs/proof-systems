use ark_ff::PrimeField;

use super::{constraint_system::SnarkyConstraintSystem, cvar::CVar, traits::SnarkyType};

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

    /// Indication that we're running the witness generation (as opposed to the circuit creation).
    has_witness: bool,

    /// Indication that we're running in prover mode (as opposed to compiling the circuit).
    // TODO: more doc on that
    as_prover: bool,
}

impl<F> RunState<F>
where
    F: PrimeField,
{
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

    // TODO: make loc argument work
    fn compute_inner<T, FUNC>(&mut self, checked: bool, _loc: String, to_compute_value: FUNC) -> T
    where
        T: SnarkyType<F>,
        FUNC: FnOnce(&dyn WitnessGeneration<F>) -> T::OutOfCircuit,
    {
        todo!()
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
        todo!()
    }
}
