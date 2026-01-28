# Snarky wrapper

Snarky, as of today, is constructed as two parts:

- a snarky wrapper, which is explained in this document
- a backend underneath that wrapper, explained in the
  [kimchi backend section](./kimchi-backend.md)

:::note

This separation exists for legacy reasons, and ideally we should merge the two into a single library.

:::

The snarky wrapper mostly exists in `checked_runner.rs`, and has the following
state:

```rust
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
    pub(crate) public_output: Vec<FieldVar<F>>,

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
    mode: Mode,
}
```

The wrapper is designed to be used in different ways, depending on the fields
set.

:::note

Ideally, we would like to only run this once and obtain a result that's an immutable compiled artifact.
Currently, `public_input`, `private_input`, `eval_constraints`, `next_var`, and `mode` all need to be mutable.
In the future these should be passed as arguments to functions, and should not exist in the state.

:::

## Public output

The support for public output is implemented as kind of a hack.

When the developer writes a circuit, they have to specify the type of the public
output.

This allows the API to save enough room at the end of the public input, and
store the variables used in the public output in the state.

When the API calls the circuit written by the developer, it expects the public
output (as a snarky type) to be returned by the function. The compilation or
proving API that ends up calling that function, can thus obtain the variables of
the public output. With that in hand, the API can continue to write the circuit
to enforce an equality constraint between these variables being returned and the
public output variable that it had previously stored in the state.

Essentially, the kimchi backend will turn this into as many wiring as there are
`FieldVar` in the public output.

During witness generation, we need a way to modify the witness once we know the
values of the public output. As the public output `FieldVar`s were generated
from the snarky wrapper (and not from the kimchi backend), the snarky wrapper
should know their values after running the given circuit.
