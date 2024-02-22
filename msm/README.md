## MSM circuit

This is a specialised circuit to compute a large MSM where the elements are
defined over a foreign field, like the one used by the Pickles verifier.
For simplicity, we suppose the foreign field is on maximum 256 bits.

The witness is splitted in two different parts:
- Columns: this is the column of the circuit.
- Lookups: this contain a list of lookups per row.
  [MVLookup](https://eprint.iacr.org/2022/1530.pdf) is used. It contains
  the individual polynomials $f_i(X)$ containing the looked up values, the
  table/polynomial $t(X)$ the polynomials $f_i(X)$ look into and the
  multiplicity polynomial $m(X)$ as defined in the paper.

The individual columns of the circuit are defined in `src/column.rs`.
The polynomials can be expressed using the expression framework, instantiated in `src/column.rs`, with
```rust
type E<Fp> = Expr<ConstantExpr<F>, MSMColumn>
```

The proof structure is defined in `src/proof.rs`. A proof consists of
commitments to the circuit columns and the lookup polynomials, in addition to
their evaluations, the evaluation points and the opening proofs.
The prover/verifier are respectively in `src/prover.rs` and `src/verifier.rs`.
Note that the prover/verifier implementation is generic enough to be used to
implement other circuits.

The protocol used is a Plonk-ish arithmetisations without the permutation
argument. The circuit is wide enough (i.e. has enough
columns) to handle one elliptic curve addition on one row.

The foreign field elements are defined with 16 limbs of 16bits. Limbs-wise
elementary addition and multiplication is used, and range checks on 16 bits is
used.
An addition of two field elements $a = (a_{1}, ..., a_{16})$ and $b = (b_{1}, ...,
b_{16})$ will be performed on one row, using one power of alpha for each (i.e one
constraint for each).

The elliptic curve points are represented in affine coordinates.
As a reminder, the equations for addition are:

```math
\lambda = \frac{y_2 - y_1}{x_2 - x_1}
```

```math
\begin{align}
x_3 & = \lambda^2 - x_{1} - x_{2} \\
y_3 & = \lambda (x_{1} - x_{3}) - y_{1}
\end{align}
```


### (De)serializer between Kimchi Foreign Field gate and 15 bits limbs

The 15/16 bulletproof challenges will be given as 88 limbs, the encoding used by Kimchi.
A circuit would be required to convert into 15 bits limbs that will be used for the MSM algorithm.
We will use one row = one decomposition.

We have the following circuit shape:

| $b_{0}$ | $b_{1}$ | $b_{2}$ | $c_{0}$ | $c_{1}$ | ... | $c_{16}$ | $b_{2, 0}$ | $b_{2, 1}$ | ... | $b_{2, 19}$ |
| ------- | ------- | ------- | ------- | ------- | --- | -------- | ---------  | ---------  | --- | ----------- |
| ...     | ...     | ...     | ...     | ...     | ... | ...      | ...        |  ...       | ... | ...         |
| ...     | ...     | ...     | ...     | ...     | ... | ...      | ...        |  ...       | ... | ...         |

We can suppose that $b_{2}$ is only on 80 bits as the input is maximum
$BN254(\mathbb{F}_{scalar})$, which is 254 bits long.
We will decompose $b_{2}$ in chunks of 4 bits:

$$b_{2} = \sum_{i = 0}^{19} b_{2, i} 2^{4 i}$$

And we will add the following constraint:

1. For the first 180 bits:

$$b_{0} + b_{1} 2^88 + b_{2, 0} * 2^{88 * 2} - \sum_{j = 0}^{11} c_{j} 2^{15 j} = 0$$

2. For the remaining 75 bits:

$$c_{12} + c_{13} * 2^{15} + c_{14} 2^{15 * 2} + c_{15} 2^{15 * 3} + c_{16} 2^{15 * 4} = \sum_{j = 1}^{19} b_{2, j} * 2^{4 j}$$

with additional lookups.

$b_{0}$, $b_{1}$ and $b_{2}$ are the decomposition on 88 bits given by the
foreign field gate in Kimchi. The values $c_{0}$, $\cdots$, $c_{16}$ are the limbs
required for the MSM circuit. Each limbs $c_{i}$ will be on 15 bits.

### Computing the coefficients of the polynomial $h(X)$


As a reminder, the polynomial we will commit to is formed by a product of the following form:

$$h(X) = \prod_{i = 0}^{N} (1 + \xi_{i}X^{2^{i}})$$

If we unfold the coefficients of the polynomial, we will get a polynomial of the form

$$h(X) = \sum_{i = 0}^{N} \zeta_{i} X^{i}$$

where $\zeta_{i}$ is a product of $\xi_{j}$, where the $j's$ forms an encoding
in base $2$ of $i$.

Let's suppose the coefficients $\zeta_{i}$ are encoded on 17 limbs on 15 bits.
Let's suppose computing the foreign field multiplication is done using $N$
additional columns $C_{1}, \cdots, C_{N}$.
Each row will be used to compute the products of one accumulated value and one
of the $\xi_{i}$.
We can use the following circuit structure to compute the elements $\zeta_{i}$:



| V                             | $l_{1}$        | $l_{2}$        | $l_{3}$        | ...      | $l_{17}$        | $C_{1}$ | $C_{2}$ | $\cdots$ | $C_{N}$ |
| ----------------------------- | -------------- | -------------- | -------------- | -------- | --------------- | ------- | ------- | -------- | ------- |
| $\xi_{0}$                   | $\zeta_{0, 1}$ | $\zeta_{0, 2}$ | $\zeta_{0, 3}$ | $\cdots$ | $\zeta_{0, 17}$ |         |         |          |         |
| $\cdots$                      |                |                |                |          |                 |         |         |          |         |
| $\xi_{N}$                   |                |                |                |          |                 |         |         |          |         |
| $\xi_{0}\xi_{1} = \zeta_{3}$          |                |                |                |          |                 |         |         |          |         |
| $\xi_{0}\xi_{2} = \zeta_{5}$          |                |                |                |          |                 |         |         |          |         |
| $\xi_{0}\xi_{1}\xi_{2} = \zeta_{3} \xi_{2} = \zeta_{7}$ |                |                |                |          |                 |         |         |          |         |
|                               |                |                |                |          |                 |         |         |          |         |
