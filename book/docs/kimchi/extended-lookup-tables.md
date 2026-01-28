# Extended lookup tables

This (old) RFC proposes an extension to our use of lookup tables using the
PLOOKUP multiset inclusion argument, so that values within lookup tables can be
chosen after the constraint system for a circuit has been fixed.

## Motivation

This extension should provide us with

- array-style lookups (`arr[i]`, where `arr` and `i` are formed of values in the
  proof witness).
- the ability to load 'bytecode' using a proof-independent commitment.
- the ability to load tables of arbitrary data for use in the circuit, allowing
  e.g. the full data of a HTTPS transcript to be entered into a proof without
  using some in-circuit commitment.
- the ability to expose tables of arbitrary in-circuit data, for re-use by other
  proofs.

These goals support 5 major use-cases:

- allow the verifier circuit to support 'custom' or user-specified gates
  - using array indexing, the use of constants and commitments/evaluations can
    be determined by the verifier index, instead of being fixed by the
    permutation argument as currently.
- allow random-access lookups in arrays as a base-primitive for user programs
- allow circuits to use low-cost branching and other familiar programming
  primitives
  - this depends on the development of a bytecode interpreter on top of the
    lookup-table primitives, where the values in the table represent the
    bytecode of the instructions.
- allow circuits to load and execute some 'user provided' bytecode
  - e.g. to run a small bytecode program provided in a transaction at
    block-production time.
- allow zkOracles to load a full HTTPS transcript without using an expensive
  in-circuit commitment.

## Detailed design

In order to support the desired goals, we first define 3 types of table:

- **fixed tables** are tables declared as part of the constraint system, and are
  the same for every proof of that circuit.
- **runtime tables** are tables whose contents are determined at proving time,
  to be used for array accesses to data from the witness. Also called dynamic
  tables in other projects.
- **side-loaded tables** are tables that are committed to in a proof-independent
  way, so that they may be reused across proofs and/or signed without knowledge
  of the specific proof, but may be different for each execution of the circuit.

These distinct types of tables are a slight fiction: often it will be desirable
to have some fixed part of runtime or side-loaded tables, e.g. to ensure that
indexing is reliable. For example, a table representing an array of values
`[x, y, z]` in the proof might be laid out as

| value1 | value2   |
| ------ | -------- |
| 0      | ?runtime |
| 1      | ?runtime |
| 2      | ?runtime |

where the `value1` entries are fixed in the constraint system. This ensure that
a malicious prover is not free to create multiple values with the same index,
such as `[(0,a), (0,x), (1,y), (2,z)]`, otherwise the value `a` might be used
where the value `x` was intended.

### Combining multiple tables

The current implementation only supports a single fixed table. In order to make
multiple tables available, we either need to run a separate PLOOKUP argument for
each table, or to concatenate the tables to form an combined table and identify
the values from each table in such a way that the prover cannot use values from
the 'wrong' table.

We already solve a similar problem with 'vector' tables -- tables where a row
contains multiple values -- where we want to ensure that the prover used an
entry `(x, y, z)` from the table, and not some parts of different entries, or
some other value entirely. In order to do this, we generate a randomising field
element `joint_combiner`, where the randomness depends on the circuit witness,
and then compute `x + y * joint_combiner + z * joint_combiner^2`. Notice that,
if the prover wants to select some `(a, b, c)` not in the table and claim that
it in fact was, they are not able to use the knowledge of the `joint_combiner`
to choose their `(a, b, c)`, since the `joint_combiner` will depend on those
values `a`, `b`, and `c`.

This is a standard technique for checking multiple equalities at once by
checking a single equality; to use it, we must simply ensure that the randomness
depends on all of the (non-constant) values in the equality.

We propose extending each table with an extra column, which we will call the
`TableID` column, which associates a different number with each table. Since the
sizes of all tables must be known at constraint system time, we can treat this
as a fixed column. For example, this converts a lookup `(a, b, c)` in the table
with ID `1` into a lookup of `(a, b, c, 1)` in the combined table, and ensures
that any value `(x, y, z)` from table ID `2` will not match that lookup, since
its representative is `(x, y, z, 2)`.

To avoid any interaction between the `TableID` column and any other data in the
tables, we use `TableID * joint_combiner^max_joint_size` to mix in the
`TableID`, where `max_joint_size` is the maximum length of any lookup or table
value. This also simplifies the 'joining' of the `table_id` polynomial
commitment, since we can straightforwardly scale it by the constant
`joint_combiner^max_joint_size` to find its contribution to every row in the
combined table.

### Sampling the `joint_combiner`

Currently, the `joint_combiner` is sampled using randomness that depends on the
witness. However, where we have runtime or side-loaded tables, a malicious
prover may be able to select values in those tables that abuse knowledge of
`joint_combiner` to create collisions.

For example, the prover could create the appearance that there is a value
`(x, y, z)` in the table with ID 1 by entering a single value `a` into the table
with ID 2, by computing

```
a =   x
    + y * joint_combiner
    + z * joint_combiner^2
    + -1 * joint_combiner^max_joint_size
```

so that the combined contribution with its table ID becomes

```
a + 2 * joint_combiner^max_joint_size
```

and thus matches exactly the combined value from `(x, y, z)` in the table with
ID 1:

```
x + y * joint_combiner + z * joint_combiner^2 + 1 * joint_combiner^max_joint_size
```

Thus, we need to ensure that the `joint_combiner` depends on the values in
runtime or side-loaded tables, so that the values in these tables cannot be
chosen using knowledge of the `joint_combiner`. To do this, we must use the
commitments to the values in these tables as part of the source of randomness
for `joint_combiner` in the prover and verifier.

In particular, this means that we must have a commitment per column for each
type of table, so that the verifier can confirm the correct construction of the
combined table.

As usual, we will use the 'transcript' of the proof so far -- including all of
these components -- as the seed for this randomness.

### Representing the combined fixed table

The fixed table can be constructed at constraint system generation time, by
extending all of the constituent tables to the same width (i.e. number of
columns), generating the appropriate table IDs array, and concatenating all of
the tables. Concretely:

Let `t[id][row][col]` be the `col`th element of the `row`th entry in the `id`th
fixed table. Let `W` be the maximum width of all of the `t[id][row]`s. For any
`t[id][row]` whose width `w` is less than `W`, pad it to width `W` by setting
`t[id][row][col] = 0` for all `w < col <= W`. Form the combined table by
concatenating all of these tables `FixedTable = t[0] || t[1] || t[2] || ...` and
store in `TableID` the table ID that the corresponding row came from. Then, for
every `output_row`, we have

```
FixedTable[output_row][col] = t[id][row][col]`
TableID[output_row] = id
where output_row = len(t[0]) + len(t[1]) + ... + len(t[id-1]) + row
```

This can be encoded as `W+1` polynomials in the constraint system, which we will
reference as `FixedTable(col)` for `0 <= col < W` and `TableID`.

For any unused entries, we use `TableID = -1`, to avoid collisions with any
tables.

### Representing the runtime table

The runtime table can be considered as a 'mask' that we apply to the fixed table
to introduce proof-specific data at runtime.

We make the simplifying assumption that an entry in the runtime table has
exactly 1 'fixed' entry, which can be used for indexing (or set to `0` if
unused), and that the table has a fixed width of `X`. We can pad any narrower
entries in the table to the full width `X` in the same way as the fixed tables
above.

We represent the masked values in the runtime table as `RuntimeTable(i)` for
`1 <= i < X`.

To specify whether a runtime table entry is applicable in the `i`th row, we use
a selector polynomial `RuntimeTableSelector`. In order to reduce the polynomial
degree of later checks, we add a constraint to check that the runtime entry is
the zero vector wherever the selector is zero:

```
RuntimeTableSelector * sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
 = sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
```

This gives the combined entry of the fixed and runtime tables as

```
sum[i=0, W, FixedTable(i) * joint_combiner^i]
+ sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
+ TableID * joint_combiner^max_joint_size
```

where we assume that `RuntimeTableSelector * FixedTable(i) = 0` for `1 <= i < W`
via our simplifying assumption above. We compute this as a polynomial
`FixedAndRuntimeTable`, giving its evaluations and openings as part of the
proof, and asserting that each entry matches the above.

The `RuntimeTableSelector` polynomial will be fixed at constraint system time,
and we can avoid opening it. However, we must provide openings for
`RuntimeTable(i)`.

The `joint_combiner` should be sampled using randomness that depends on the
individual `RuntimeTable(i)`s, to ensure that the runtime values cannot be
chosen with prior knowledge `joint_combiner`.

### Representing the side-loaded tables

The side-loaded tables can be considered as additional 'masks' that we apply to
the combined fixed and runtime table, to introduce this side-loaded data.

Again, we make the simplifying assumption that an entry from a side-loaded table
has exactly 1 'fixed' entry, which can be used for indexing (or set to `0` if
unused). We also assume that at most 1 side-loaded table contributes to each
entry.

In order to compute the lookup multiset inclusion argument, we also need the
combined table of all 3 table kinds, which we will call `LookupTable`. We can
calculate the contribution of the side-loaded table for each lookup as

```
LookupTable - FixedAndRuntimeTable
```

We will represent the polynomials for the side-loaded tables as
`SideLoadedTable(i, j)`, where `i` identifies the table, and `j` identifies the
column within that table. We also include polynomials `SideLoadedCombined(i)` in
the proof, along with their openings, where

```
SideLoadedCombined(i)
  = sum[j=1, ?, SideLoadedTable(i, j) * joint_combiner^(j-1)]
```

and check for consistency of the evaluations and openings when verifying the
proof.

The `SideLoadedTable` polynomials are included in the proof, but we do so 'as
if' they had been part of the verification index (ie. without any proof-specific
openings), so that they may be reused across multiple different proofs without
modification.

The `joint_combiner` should be sampled using randomness that depends on the
individual `SideLoadedTable(i,j)`s, to ensure that the side-loaded values cannot
be chosen with prior knowledge `joint_combiner`.

_Note: it may be useful for the verifier to pass the `SideLoadedTable(i,j)`s as
public inputs to the proof, so that the circuit may assert that the table it had
side-loaded was signed or otherwise correlated with a cryptographic commitment
that it had access to. The details of this are deliberately elided in this RFC,
since the principle and implementation are both fairly straightforward._

### Position-independence of side-loaded tables

We want to ensure that side-loaded tables are maximally re-usable across
different proofs, even where the 'position' of the same side-loaded table in the
combined table may vary between proofs. For example, we could consider a
'folding' circuit `C` which takes 2 side-loaded tables `t_in` and `t_out`, where
we prove

```
C(t_0, t_1)
C(t_1, t_2)
C(t_2, t_3)
...
```

and the 'result' of the fold is the final `t_n`. In each pair of executions in
the sequence, we find that `t_i` is used as both `t_in` and `t_out`, but we
would like to expose the same table as the value for each.

To achieve this, we use a permutation argument to 'place' the values from each
side-loaded table at the correct position in the final table. Recall that every
value

```
LookupTable - FixedAndRuntimeTable
```

is either 0 (where no side-loaded table contributes a value) or the value of
some row in `SideLoadedCombined(i) * joint_combiner` from the table `i`.

For the `0` differences, we calculate a permutation between them all and the
single constant `0`, to ensure that `LookupTable = FixedAndRuntimeTable`. For
all other values, we set-up a permutation based upon the side-loaded table
relevant to each value.

Thus, we build the permutation accumulator

```
LookupPermutation
 * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
     + gamma + beta * Sigma(7))
 * (SideLoadedCombined(0) + gamma + beta * Sigma(8))
 * (SideLoadedCombined(1) + gamma + beta * Sigma(9))
 * (SideLoadedCombined(2) + gamma + beta * Sigma(10))
 * (SideLoadedCombined(3) + gamma + beta * Sigma(11))
 =
   LookupPermutation[prev]
   * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
       + gamma + x * beta * shift[7])
   * (SideLoadedCombined(0) + gamma + x * beta * shift[8])
   * (SideLoadedCombined(1) + gamma + x * beta * shift[9])
   * (SideLoadedCombined(2) + gamma + x * beta * shift[10])
   * (SideLoadedCombined(3) + gamma + x * beta * shift[11])
```

where `shift[0..7]` is the existing `shift` vector used for the witness
permutation, and the additional values above are chosen so that `shift[i] * w^j`
are distinct for all `i` and `j`, and `Sigma(_)` are the columns representing
the permutation. We then assert that

```
Lagrange(0)
  * (LookupPermutation * (0 + gamma + beta * zero_sigma)
    - (0 + gamma + beta * shift[len(shift)-1]))
  = 0
```

to mix in the contributions for the constant `0` value, and

```
Lagrange(n-ZK_ROWS) * (LookupPermutation - 1) = 0
```

to ensure that the permuted values cancel.

Note also that the permutation argument allows for interaction **between**
tables, as well as injection of values into the combined lookup table. As a
result, the permutation argument can be used to 'copy' parts of one table into
another, which is likely to be useful in examples like the 'fold' one above, if
some data is expected to be shared between `t_in` and `t_out`.

### Permutation argument for cheap array lookups

It would be useful to add data to the runtime table using the existing
permutation arguments rather than using a lookup to 'store' data. In particular,
the polynomial degree limits the number of lookups available per row, but we are
able to assert equalities on all 7 permuted witness columns using the existing
argument. By combining the existing `PermutationAggreg` with
`LookupPermutation`, we can allow all of these values to interact.

Concretely, by involving the original aggregation and the first row of the
runtime table, we can construct the permutation

```
LookupPermutation
 * PermutationAggreg
 * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
     + gamma + beta * Sigma(7))
 * (SideLoadedCombined(0) + gamma + beta * Sigma(8))
 * (SideLoadedCombined(1) + gamma + beta * Sigma(9))
 * (SideLoadedCombined(2) + gamma + beta * Sigma(10))
 * (SideLoadedCombined(3) + gamma + beta * Sigma(11))
 * (RuntimeTable(1) + gamma + beta * Sigma(12))
 =
   LookupPermutation[prev]
   * PermutationAggreg[prev]
   * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
       + gamma + x * beta * shift[7])
   * (SideLoadedCombined(0) + gamma + x * beta * shift[8])
   * (SideLoadedCombined(1) + gamma + x * beta * shift[9])
   * (SideLoadedCombined(2) + gamma + x * beta * shift[10])
   * (SideLoadedCombined(3) + gamma + x * beta * shift[11])
   * (RuntimeTable(1) + gamma + x * beta * shift[12])
```

to allow interaction between any of the first 7 witness rows and the first row
of the runtime table. Note that the witness rows can only interact with the
side-loaded tables when they contain a single entry due to their use of
`joint_combiner` for subsequent entries, which is sampled using randomness that
depends on this witness.

In order to check the combined permutation, we remove the final check from the
existing permutation argument and compute the combined check of both permutation
arguments:

```
Lagrange(n-ZK_ROWS) * (LookupPermutation * PermutationAggreg - 1) = 0
```

### Full list of polynomials and constraints

#### Constants

- `shift[0..14]` (`shift[0..7]` existing)
- `zero_sigma`
- `joint_combiner` (existing)
- `beta` (existing)
- `gamma` (existing)
- `max_joint_size` (existing, integer)

This results in 8 new constants.

#### Polynomials without per-proof evaluations

- `TableID` (verifier index)
- `FixedTable(i)` (verifier index, existing)
- `RuntimeTableSelector` (verifier index)
- `SideLoadedTable(i, j)` (proof)

This results in 2 new polynomials + 1 new polynomial for each column of each
side-loaded table.

#### Polynomials with per-proof evaluations + openings

- `LookupTable` (existing)
- `RuntimeTable(i)`
- `FixedAndRuntimeTable`
- `PermutationAggreg` (existing)
- `LookupPermutation`
- `Sigma(i)` (existing for `0 <= i < 7`, new for `7 <= i < 13`)

This results in 8 new polynomial evaluations + 1 new evaluation for each column
of the runtime table.

#### Constraints

- permutation argument (existing, remove `n-ZK_ROWS` check) (elided)
- lookup argument (existing) (elided)
- runtime-table consistency
  ```
  RuntimeTableSelector * sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
   = sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
  ```
- fixed and runtime table evaluation
  ```
  FixedAndRuntimeTable
    = sum[i=0, W, FixedTable(i) * joint_combiner^i]
      + sum[i=1, X, RuntimeTable(i) * joint_combiner^i]
      + TableID * joint_combiner^max_joint_size
  ```
- lookup permutation argument
  ```
  LookupPermutation
   * PermutationAggreg
   * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
       + gamma + beta * Sigma(7))
   * (SideLoadedCombined(0) + gamma + beta * Sigma(8))
   * (SideLoadedCombined(1) + gamma + beta * Sigma(9))
   * (SideLoadedCombined(2) + gamma + beta * Sigma(10))
   * (SideLoadedCombined(3) + gamma + beta * Sigma(11))
   * (RuntimeTable(1) + gamma + beta * Sigma(12))
   =
     LookupPermutation[prev]
     * PermutationAggreg[prev]
     * ((LookupTable - FixedAndRuntimeTable) * joint_combiner^(-1)
         + gamma + x * beta * shift[7])
     * (SideLoadedCombined(0) + gamma + x * beta * shift[8])
     * (SideLoadedCombined(1) + gamma + x * beta * shift[9])
     * (SideLoadedCombined(2) + gamma + x * beta * shift[10])
     * (SideLoadedCombined(3) + gamma + x * beta * shift[11])
     * (RuntimeTable(1) + gamma + x * beta * shift[12])
  ```
- lookup permutation initializer
  ```
  Lagrange(0)
    * (LookupPermutation * (0 + gamma + beta * zero_sigma)
      - (0 + gamma + beta * shift[len(shift)-1]))
    = 0
  ```
- lookup permutation finalizer
  ```
  Lagrange(n-ZK_ROWS) * (LookupPermutation - 1) = 0
  ```

This results in 5 new checks, and the removal of 1 old check.

The lookup permutation argument (and its columns) can be elided when it is
unused by either the side-loaded table or the runtime table. Similarly, the
runtime table checks (and columns) can be omitted when there is no runtime
table.

## Drawbacks

This proposal increases the size of proofs, and increases the number of checks
that the verifier must perform, and thus the cost of the recusive verifier. This
also increases the complexity of the proof system.

## Rationale and alternatives

### Why is this design the best in the space of possible designs?

This design combines the 3 different 'modes' of random access memory, roughly
approximating `ROM -> RAM` loading, `disk -> RAM` loading, and `RAM r/w`. This
gives the maximum flexibility for circuit designers, and each primitive has uses
for projects that we are pursuing.

This design has been refined over several iterations to reduce the number of
components exposed in the proof and the amount of computation that the verifier
requires. The largest remaining parts represent the data itself and the method
for combining them, where simplifying assumptions have been made to minimize
their impact while still satisfying the design constraints.

### What other designs have been considered and what is the rationale for not choosing them?

Other designs building upon the lookup primitive reduce on some subset of this
design, or on relaxing a design constraint that would remove some useful /
required functionality.

### What is the impact of not doing this?

We are currently unable to expose certain useful functionality to users of
Snapps / SnarkyJS, and are missing the ability to use that same functionality
for important parts of the zkOracles ecosystem (such as parsing / scraping).

We also are currently forced to hard-code any constraints that we need for
particular uses in the verifier circuit, and users are unable to remove the
parts they do not need and to replace them with other useful constraints that
their circuits might benefit from.

The Mina transaction model is unable to support a bytecode interpreter without
this or similar extensions.

## Prior art

_(Elided)_

## Unresolved questions

### What parts of the design do you expect to resolve through the RFC process before this gets merged?

- The maximum number of tables / entries of each kind that we want to support in
  the 'standard' protocol.
- Validation (or rejection) of the simplifying assumptions.
- Confirmation of the design constraints, or simplifications thereto.
- Necessity / utility of the permutation argument.

### What parts of the design do you expect to resolve through the implementation of this feature before merge?

None, this RFC has been developed in part from an initial design and iteration
on implementations of parts of that design.

### What related issues do you consider out of scope for this RFC that could be addressed in the future independently of the solution that comes out of this RFC?

- Bytecode design and implementation details.
- Mina transaction interface for interacting with these features.
- Snarky / SnarkyJS interface for interacting with these features.
