# Vars

In this section we will introduce two types of variables:

- Circuit vars, or `FieldVar`s, which are low-level variables representing field
  elements.
- Snarky vars, which are high-level variables that user can use to create more
  meaningful programs.

## Circuit vars

In snarky, we first define circuit variables (TODO: rename Field variable?)
which represent field elements in a circuit. These circuit variables, or cvars,
can be represented differently in the system:

```rust
pub enum FieldVar<F>
where
    F: PrimeField,
{
    /// A constant.
    Constant(F),

    /// A variable that can be referred to via a `usize`.
    Var(usize),

    /// The addition of two other [FieldVar]s.
    Add(Box<FieldVar<F>>, Box<FieldVar<F>>),

    /// Scaling of a [FieldVar].
    Scale(F, Box<FieldVar<F>>),
}
```

One can see a FieldVar as an AST, where two atoms exist: a `Var(usize)` which
represents a private input, and a `Constant(F)` which represents a constant.
Anything else represents combinations of these two atoms.

### Constants

Note that a circuit variable does not represent a value that has been
constrained in the circuit (yet). This is why we need to know if a cvar is a
constant, so that we can avoid constraining it too early. For example, the
following code does not encode 2 or 1 in the circuit, but will encode 3:

```rust
let x: FieldVar = state.exists(|_| 2) + state.exists(|_| 3);
state.assert_eq(x, y); // 3 and y will be encoded in the circuit
```

whereas the following code will encode all variables:

```rust
let x = y + y;
let one: FieldVar = state.exists(|_| 1);
assert_eq(x, one);
```

### Non-constants

Right after being created, a `FieldVar` is not constrained yet, and needs to be
constrained by the application. That is unless the application wants the
`FieldVar` to be a constant that will not need to be constrained (see previous
example) or because the application wants the `FieldVar` to be a random value
(unlikely) (TODO: we should add a "rand" function for that).

In any case, a circuit variable which is not a constant has a value that is not
known yet at circuit-generation time. In some situations, we might not want to
constrain the

### When do variables get constrained?

In general, a circuit variable only gets constrained by an assertion call like
`assert` or `assert_equals`.

When variables are added together, or scaled, they do not directly get
constrained. This is due to optimizations targeting R1CS (which we don't support
anymore) that were implemented in the original snarky library, and that we have
kept in snarky-rs.

Imagine the following example:

```rust
let y = x1 + x2 + x3 +.... ;
let z = y + 3;
assert_eq(y, 6);
assert_eq(z, 7);
```

The first two lines will not create constraints, but simply create minimal ASTs
that track all of the additions.

Both assert calls will then reduce the variables to a single circuit variable,
creating the same constraints twice.

For this reason, there's a function `seal()` defined in pickles and snarkyjs.
(TODO: more about `seal()`, and why is it not in snarky?) (TODO: remove the R1CS
optimization)

## Snarky vars

Handling `FieldVar`s can be cumbersome, as they can only represent a single
field element. We might want to represent values that are either in a smaller
range (e.g. [booleans](./booleans.md)) or that are made out of several
`FieldVar`s.

For this, snarky's API exposes the following trait, which allows users to define
their own types:

```rust
pub trait SnarkyType<F>: Sized
where
    F: PrimeField,
{
    /// ?
    type Auxiliary;

    /// The equivalent type outside of the circuit.
    type OutOfCircuit;

    const SIZE_IN_FIELD_ELEMENTS: usize;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary);

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self;

    fn check(&self, cs: &mut RunState<F>);

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary);

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self;

    fn constraint_system_auxiliary() -> Self::Auxiliary;

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary);

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit;
}
```

Such types are always handled as `OutOfCircuit` types (e.g. `bool`) by the
users, and as a type implementing `SnarkyType` by snarky (e.g.
[`Boolean`](./booleans.md)). Thus, the user can pass them to snarky in two ways:

**As public inputs**. In this case they will be serialized into field elements
for snarky before witness generation (via the
`value_to_field_elements()` function)

**As private inputs**. In this case, they must be created using the `compute()`
function with a closure returning an `OutOfCircuit` value by the user. The call
to `compute()` will need to have some type hint, for snarky to understand what
`SnarkyType` it is creating. This is because the relationship is currently only
one-way: a `SnarkyType` knows what out-of-circuit type it relates to, but not
the other way is not true. (TODO: should we implement that though?)

A `SnarkyType` always implements a `check()` function, which is called by snarky
when `compute()` is called to create such a type. The `check()` function is
responsible for creating the constraints that sanitize the newly-created
`SnarkyType` (and its underlying `FieldVar`s). For example, creating a boolean
would make sure that the underlying `FieldVar` is either 0 or 1.
