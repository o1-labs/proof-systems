## MSM circuit

This is a specialised circuit to compute a large MSM where the elements are
defined over a foreign field, like the one used by the Pickles verifier. For
simplicity, we suppose the foreign field is on maximum 256 bits.

The witness is splitted in two different parts:

- Columns: this is the column of the circuit.
- Lookups: this contain a list of lookups per row.
  [MVLookup](https://eprint.iacr.org/2022/1530.pdf) is used. It contains the
  individual polynomials $f_i(X)$ containing the looked up values, the
  table/polynomial $t(X)$ the polynomials $f_i(X)$ look into and the
  multiplicity polynomial $m(X)$ as defined in the paper.

The individual columns of the circuit are defined in `src/column.rs`. The
polynomials can be expressed using the expression framework, instantiated in
`src/column.rs`, with

```rust
type E<Fp> = Expr<ConstantExpr<F>, MSMColumn>
```

The proof structure is defined in `src/proof.rs`. A proof consists of
commitments to the circuit columns and the lookup polynomials, in addition to
their evaluations, the evaluation points and the opening proofs. The
prover/verifier are respectively in `src/prover.rs` and `src/verifier.rs`. Note
that the prover/verifier implementation is generic enough to be used to
implement other circuits.

The protocol used is a Plonk-ish arithmetisations without the permutation
argument. The circuit is wide enough (i.e. has enough columns) to handle one
elliptic curve addition on one row.

The foreign field elements are defined with 16 limbs of 16bits. Limbs-wise
elementary addition and multiplication is used, and range checks on 16 bits is
used. An addition of two field elements $a = (a_{1}, ..., a_{16})$ and
$b = (b_{1}, ...,
b_{16})$ will be performed on one row, using one power of alpha
for each (i.e one constraint for each).

The elliptic curve points are represented in affine coordinates. As a reminder,
the equations for addition are:

```math
\lambda = \frac{y_2 - y_1}{x_2 - x_1}
```

```math
\begin{align}
x_3 & = \lambda^2 - x_{1} - x_{2} \\
y_3 & = \lambda (x_{1} - x_{3}) - y_{1}
\end{align}
```
