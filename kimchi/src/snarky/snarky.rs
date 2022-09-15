// Shamelessly copied from Snarky's snark_intf.ml

pub trait SnarkyVar<F>: Clone {
    // TODO: Add, mul, etc.
    fn constant(f: F) -> Self;
}

pub trait SnarkyType<F> {
    type Var: SnarkyVar<F>;
    type Constraint;

    type OutOfCircuit;
    type Auxiliary;

    fn to_field_elements(&self) -> (Vec<Self::Var>, Self::Auxiliary);
    fn of_field_elements(x: (Vec<Self::Var>, Self::Auxiliary)) -> Self;

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);
    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit;

    const SIZE_IN_FIELD_ELEMENTS: usize;

    fn constraint_system_auxiliary() -> Self::Auxiliary;
    fn check<CS>(&self)
    where
        CS: SnarkyConstraintSystem<F, Var = Self::Var, Constraint = Self::Constraint>;
}

pub enum HandleResponse<A, PrevRequest> {
    Respond(A),
    Via(PrevRequest),
}

pub trait SnarkyConstraintSystem<F> {
    type Var: SnarkyVar<F>;
    type Constraint;
    type Request;
    type Response;

    type AsProver: SnarkyAsProver<F, Var = Self::Var, Request = Self::Request>;

    fn assert(&mut self, constraint: Self::Constraint) -> ();
    fn assert_all(&mut self, constraint: impl Iterator<Item = Self::Constraint>) -> ();
    fn assert_r1cs(&mut self, a: &Self::Var, b: &Self::Var, c: &Self::Var) -> ();
    fn assert_square(&mut self, a: &Self::Var, b: &Self::Var) -> ();

    fn as_prover<Fun>(&mut self, f: Fun) -> ()
    where
        Fun: FnOnce(&Self::AsProver);

    fn compute<InCircuit, Fun>(&mut self) -> InCircuit
    where
        InCircuit: SnarkyType<F, Var = Self::Var, Constraint = Self::Constraint>,
        Fun: FnOnce(&Self::AsProver) -> InCircuit::OutOfCircuit;

    fn if_<InCircuit>(&mut self, then_: InCircuit, else_: InCircuit) -> InCircuit
    where
        InCircuit: SnarkyType<F, Var = Self::Var, Constraint = Self::Constraint>;

    /* TODO
    fn handle<Request, Response, Handler, Res, Fun>(handle: Handler, f: Fun) -> Res
    where
        Handler: Fn(Self::Request) -> HandleResponse<Response, Self::Request>,
        Fun: Fn(&mut impl SnarkyConstraintSystem<Var= Self::Var, Constraint= Self::Constraint, Request = Request, Response = Response>) -> Res;*/
}

pub trait SnarkyAsProver<F> {
    type Var: SnarkyVar<F>;
    type Request;
    type Response;

    fn read_var(&self, var: &Self::Var) -> F;

    fn read<InCircuit>(&self, var: &InCircuit) -> InCircuit::OutOfCircuit
    where
        InCircuit: SnarkyType<F, Var = Self::Var>,
    {
        let (field_vars, aux) = var.to_field_elements();
        let fields = field_vars.iter().map(|x| self.read_var(x)).collect();
        InCircuit::value_of_field_elements((fields, aux))
    }

    fn request(&self, request: Self::Request) -> Self::Response;
}
