# Circuit generation

In circuit generation mode, the `has_witness` field of `RunState` is set to the
default `CircuitGeneration`, and the program of the user is ran to completion.

During the execution, the different snarky functions called on `RunState` will
create [internal variables](./vars.md) as well as constraints.

## Creation of variables

[Variables](./vars.md) can be created via the `compute()` function, which takes
two arguments:

- A `TypeCreation` toggle, which is either set to `Checked` or `Unsafe`. We will
  describe this below.
- A closure representing the actual computation behind the variable. This
  computation will only take place when real values are computed, and can be
  non-deterministic (e.g. random, or external values provided by the user). Note
  that the closure takes one argument: a `WitnessGeneration`, a structure that
  allows you to read the runtime values of any variables that were previously
  created in your program.

The `compute()` function also needs a type hint to understand what type of
[snarky type](./vars.md#snarky-vars) it is creating.

It then performs the following steps:

- creates enough [`FieldVar`](./vars#circuit-vars) to hold the value to be
  created
- retrieves the auxiliary data needed to create the snarky type (TODO: explain
  auxiliary data) and create the [`snarky variable`](./vars.md#snarky-vars) out
  of the `FieldVar`s and the auxiliary data
- if the `TypeCreation` is set to `Checked`, call the `check()` function on the
  snarky type (which will constrain the value created), if it is set to `Unsafe`
  do nothing (in which case we're trusting that the value cannot be malformed,
  this is mostly used internally and it is highly-likely that users directly
  making use of `Unsafe` are writing bugs)

:::note

At this point we only created variables to hold future values, and made sure that they are constrained.
The actual values will fill the room created by the `FieldVar` only during the witness generation phase.

:::

## Constraints

All other functions exposed by the API are basically here to operate on
variables and create constraints in doing so.
