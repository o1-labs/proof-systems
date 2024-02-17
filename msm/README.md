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


### How is it implemented?

Let's start with a simple example. For the formal generialization, see the [MSM RFC](https://github.com/o1-labs/rfcs/blob/msm/00XX-efficient-msms-for-non-native-pickles-verification.md).

Let define the base $G_{1}$, $G_{2}$ and $G_{3}$.
Let's suppose we have to compute the following (small) MSM:

$$
10 G_{1} + 3 G_{2} + 19 G_{3}
$$

We will split the coefficients in base 9, and our field is $\mathbb{F}_{23}$. It means we have the following "scaled" basis:

$$
G_{1}, 9 G_{1}, 18 G_{1}, G_{2}, 9 G_{2}, 18 G_{2}, G_{3}, 9 G_{3}, 18 G_{3}
$$

Our MSM will be decomposed in the new basis as:

$$
\begin{align}
& 1 G_{1} + 1 [9 G_{1}] + 0 [18 G_{1}] + \\
& 3 G_{2} + 0 [9 G_{2}] + 0 [18 G_{2}] + \\
& 1 G_{3} + 0 [9 G_{3}] + 1 [18 G_{3}]
\end{align}
$$

We notice that we can represent the computation in 3 sets of new 3 bases:
$\{G_{1}, G_{2}, G_{3}\}$, $\{[9]G_{1}, [9]G_{2}, [9]G_{3} \}$and $\{[18]G_{1},
[18]G_{2}, [18]G_{3} \}$.

What we will do is performing 3 different proofs, which will compute separately the three following MSM:

$$
1 G_{1} + 3 G_{2} + 1 G_{3}
$$

$$
1 [9]G_{1} + 0 [9]G_{2} + 0 [9]G_{3}
$$

$$
0 [18]G_{1} + 0 [18]G_{2} + 1 [18] G_{3}
$$

From there, we will "bucket" the coefficients. We create an array of size 9, and add each individual scaled base element:

$$
\begin{align}
buckets[0] & = [18 G_{1}] \\
           & + [9 G_{2}] + [18 G_{2}] \\
           & + [9 G_{3}]
\end{align}
$$

$$
\begin{align}
buckets[1] & = [G_{1}] + [9 G_{1}] \\
           & + [18 G_{3}] + [18 G_{3}]
\end{align}
$$

$$
\begin{align}
buckets[2] & = \emptyset \\
buckets[3] & = G_{2} \\
buckets[4] & = \emptyset \\
buckets[5] & = \emptyset \\
buckets[6] & = \emptyset \\
buckets[7] & = \emptyset \\
buckets[8] & = \emptyset
\end{align}
$$

*Note that the $buckets[0]$ can be set to the empty set like the others, it is
only to be complete with the decomposition given above

The elements in the bucket are added "on-the-fly", while processing the MSM
individual elements and bucketing by the coefficients.

From there, we can iterate over the buckets, and multiply by the coefficients of the currently processed bucket.

```
total = 0_{G}
for i = 0 to 8:
  total += i * bucket[i]
```

By doing this operation, we provided a way to save computation of scalar
multiplications over the curve, which is an expensive operation. We only do
perform one scalar multiplication of a "running sum" of scaled basis elements.


### Step 1: computing the coefficients in the scaled basis

To start, we want to make a proof that the prover computed correctly the
coefficients for the scaled basis. As a reminder, we will use a basis of 17
limbs of 15 bits.
The scalars of the MSM are field elements of the scalar/base field of Vesta.
The elements are 255bits long. Therefore, we can encode each value in exactly 17
chunks of 15 bits.

The circuit for this proof will be the following:
The inputs will be two field elements of the $F_{scalar}(BN254)$. The first
field element will encode the first 240 bits of the challenge, and the second
the last 15 bits.

We will have 2 + 17 columns.
For the coefficients $c_{1}$, $c_{2}$, ..., $c_{2^15}$, we will have the
following trace:

| C          | $DEC_{1}$         | $DEC_{2}$         | ... |   $DEC_{16}$      |
|-------     |------------       |------------       | --- | ------------      |
| $c_{1}$    |   $c_{1, 1}$      |   $c_{1, 2}$      | ... |   $c_{1, 16}$     |
| $c_{2}$    |   $c_{2, 1}$      |   $c_{2, 2}$      | ... |   $c_{2, 16}$     |
|  ...       |  ...              |   ...             | ... |    ...            |
| $c_{2^15}$ |   $c_{2^{15}, 1}$ |   $c_{2^{15}, 2}$ | ... |  $c_{2^{15}, 16}$ |

The constraint for each row will be $c_{i} = \sum 2^{k * j} c_{i, j}$ and 16
range check in $[0, 2^{15}[$ will be performed on each column $DEC_{i}$.
MVLookup will be used.

### Mina proof structure

As a reminder, we have the following diagram:


```
Step
    \
     \
     ----> Wrap
     /
    /
Step
```

A Wrap proof verifies maximum two step proofs.
Wrap circuits are encoded into the scalar field of Pallas.
Step circuits are encoded in the scalar field of Vesta.
