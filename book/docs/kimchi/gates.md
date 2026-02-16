## Custom gates

The goal of this section is to draw the connections between the practical aspect
of designing custom gates and the theory behind it.

First, suppose we had the following layout of gates. This means that our circuit
has four gates: a (single) generic gate, a (non-optimized) complete add, and
then two different `Example` gates that we just make up for the example;
`ExamplePairs` and `ExampleTriples`.

| row | `GateType::`     | 0    | 1    | 2    | 3    | 4    | 5    | 6     | 7        | 8   | 9       | 10        | 11  | 12  | 13  | 14  |
| --- | ---------------- | ---- | ---- | ---- | ---- | ---- | ---- | ----- | -------- | --- | ------- | --------- | --- | --- | --- | --- |
| 0   | `Generic`        | `l`  | `r`  | `o`  |      |      |      |       |          |     |         |           |     |     |     |     |
| 1   | `CompleteAdd`    | `x1` | `y1` | `x2` | `y2` | `x3` | `y3` | `inf` | `same_x` | `s` | `inf_z` | `x21_inv` |     |     |     |     |
| 2   | `ExamplePairs`   | `a`  | `e`  | `i`  | `o`  | `u`  | `y`  |       |          |     |         |           |     |     |     |     |
| 3   | `ExampleTriples` | `a`  | `b`  | `c`  | `d`  | `e`  | `f`  | `g`   | `h`      | `i` | `j`     | `k`       | `l` | `m` | `n` | `o` |

The most important aspect to take into account when you are designing a new
custom gate is writing the actual description of the new functionality. For
this, we are using the `Expression` framework that allows us to write equations
generically by representing each column of the table (wire) as a variable. Then
we can write operations between them and define the **gate constraints**. From a
mathematical perspective, these will have the shape of multivariate polynomials
of as many variables as columns in the table (currently 15 for Kimchi) that is
constrained to equal 0.

In our example, we would define equations that represent the operations carried
out by each of the gates. In the following equations we use the variable names
that we wrote in the cells above, and we don't imply that the same name in a
different row correspond to the same value (we are not imposing equalities
between gates yet):

`Generic`:

1. `l` $\cdot c_l +$ `r` $\cdot c_r +$ `o` $\cdot c_o +$ `l` $\cdot$ `r`
   $\cdot c_m + c_c = 0$

`CompleteAdd`:

1. `x21_inv` $\cdot ($ `x2` $-$ `x1` $) - ( 1 - $ `same_x`$) = 0$
2. `same_x` $\cdot ($ `x2` $-$ `x1` $) = 0$
3. `same_x` $\cdot ( 2 \cdot$ `s` $\cdot$ `y1` $- 3 \cdot$
   `x1`$^2) + ( 1 - $ `same_x` $) \cdot \big(($`x2` $-$ `x1` $) \cdot$ `s` $-$
   `y2` + `y1` $\big) = 0$
4. `x1` $+$ `x2` $+$ `x3` $-$ `s`$^2 = 0$
5. `s` $\cdot ($ `x1` $-$ `x3` $) -$ `y1` $-$ `y3`$ = 0$
6. $($ `y2` $-$ `y1` $) \cdot ($ `same_x` $-$ `inf` $) = 0$
7. $($ `y2` $-$ `y1` $) \cdot$ `inf_z` $-$ `inf` $ = 0$

`ExamplePairs`:

1. `a` $-$ `e` $= 0$
2. `i` $-$ `o` $= 0$
3. `u` $-$ `y` $= 0$

`ExampleTriples`:

1. `a` $\cdot$ `b` $\cdot$ `c` $= 0$
2. `d` $\cdot$ `e` $\cdot$ `f` $= 0$
3. `g` $\cdot$ `h` $\cdot$ `i` $= 0$
4. `j` $\cdot$ `k` $\cdot$ `l` $= 0$
5. `m` $\cdot$ `n` $\cdot$ `o` $= 0$

Nonetheless, when we write these constraints in `proof-systems`, we use a shared
framework that helps us use the columns in each row as placeholders. For
example, the `i`-th column of the current row `Curr` is represented as:

```rust
E::<F>::cell(Column::Witness(i), CurrOrNext::Curr)
```

where the `E` type is a shorthand for `Expr<ConstantExpr>`. More succinctly, we
refer to the above simply as:

```rust
witness_curr(i)
```

For readability, let's just refer to them here as `w0..w14`. Then, the above
constraints would look like the following:

`Generic`:

1. `w0` $\cdot c_l +$ `w1` $\cdot c_r +$ `w2` $\cdot c_o +$ `w0` $\cdot$ `w1`
   $\cdot c_m + c_c = 0$

`CompleteAdd`:

1. `w10` $\cdot ($ `w2` $-$ `w0` $) - ( 1 - $ `w7`$) = 0$
2. `w7` $\cdot ($ `w2` $-$ `w0` $) = 0$
3. `w7` $\cdot ( 2 \cdot$ `w8` $\cdot$ `w1` $- 3 \cdot$
   `w0`$^2) + ( 1 - $ `w7` $) \cdot \big(($`w2` $-$ `w0` $) \cdot$ `w8` $-$
   `w3` + `w1` $\big) = 0$
4. `w0` $+$ `w2` $+$ `w4` $-$ `w8`$^2 = 0$
5. `w8` $\cdot ($ `w0` $-$ `w4` $) -$ `w1` $-$ `w4`$ = 0$
6. $($ `w3` $-$ `w1` $) \cdot ($ `w7` $-$ `w6` $) = 0$
7. $($ `w3` $-$ `w1` $) \cdot$ `w9` $-$ `w6` $ = 0$

`ExamplePairs`:

1. `w0` $-$ `w1` $= 0$
2. `w2` $-$ `w3` $= 0$
3. `w4` $-$ `w5` $= 0$

`ExampleTriples`:

1. `w0` $\cdot$ `w1` $\cdot$ `w2` $= 0$
2. `w3` $\cdot$ `w4` $\cdot$ `w5` $= 0$
3. `w6` $\cdot$ `w7` $\cdot$ `w8` $= 0$
4. `w9` $\cdot$ `w10` $\cdot$ `w11` $= 0$
5. `w12` $\cdot$ `w13` $\cdot$ `w14` $= 0$

Looking at the list of equations, each of them look like polynomials in the
variables `w0..w14`, constrained to zero. But so far, the type of equations we
had studied were univariate (i.e. $f(X)$ rather than $f(X_0,...,X_{14})$). But
this will not be a problem, since these _multivariate_ equations will soon
become univariate with a simple trick: **interpolation**. Right now, we are
describing the gate constraints row-wise (i.e. _horizontally_). But as we said
before, our domain will be determined by the number of rows; we will transform
these equations to a _vertical_ and _univariate_ behaviour. The strategy to
follow will be obtaining witness polynomials that evaluate to the cells of the
execution trace.

**First**, note that so far we didn't mention any values for the `w0..w14`
terms, but instead they are placeholders for _what is yet to come_. And what is
this you may ask: the **witness of the relation**. Put it another way, the
witness will be the instantiation of the cells of the table that will make all
of the above constraints hold. And where do we get these values from? Well, the
**prover will know or will compute them**.

**Second**, we count the number of rows that we ended up with: here it's four
(conveniently, a power of two). What we want to do is to create as many witness
polynomials as the number of columns in the execution trace. These polynomials,
that we can call $w_0(X),...,w_{14}(X)$, must be design to evaluate to the cells
of the trace. Formally we define each $w_j(X)$ as:

$$ \mathbb{G} = <g>:\quad w_j(g^i) = \text{trace}[i, j]$$

Meaning that $w_i(x)$ returns the $i$-th column of the $x$-th row of the
execution trace. And how can we create such polynomials? We will use
interpolation, which can be efficiently computed over power-of-two-sized groups,
as it is the case in the example. Recalling **Lagrangian terms**, they act like
linearly independent selectors over a set, in particular:

> Let $\mathbb{G}$ be a multiplicative group formed by the powers of a generator
> $g$. Given any element $x$ in the group, the $i$-th Lagrangian term evaluates
> to $1$ iff $x=g^i$ and $0$ iff $x\neq g^i$.

$$\forall\ x \in \mathbb{G}: \quad \mathcal{L}_{g^i}^{\mathbb{G}}(x) = 1 \iff x = \theta \quad \text{ and } \quad \mathcal{L}_{g^i}^{\mathbb{G}}(x) = 0 \iff x \neq \theta$$

Given that our group has size $4$, the number of rows (ignoring ZK for now),
$\mathbb{G}$ will be the set $\{1, g, g^2, g^3\}$. This means that we can build
such $15$ witness polynomials as:

$$\forall j \in [0..15):\quad w_j(X) = \sum_{i=0}^{3} \text{trace}[i,j] \cdot \mathcal{L}_{g^i}^{\mathbb{G}} (X) $$

Then, the above constraints will become the following equations using our $15$
univariate witness polynomials:

`Generic`:

1. $w_0(X)\cdot c_l + w_1(X) \cdot c_r + w_2(X) \cdot c_o + w_0(X) \cdot w_1(X) \cdot c_m + c_c = 0$

`CompleteAdd`:

1. $w_{10}(X) \cdot \big( w_2(X) - w_0(X)\big) - \big( 1 -  w_7(X)\big) = 0$
2. $w_7(X) \cdot ( w_2(X) - w_0(X) ) = 0$
3. $w_7(X) \cdot \big( 2 \cdot w_8(X) \cdot w_1(X) - 3 \cdot w_0(X)^2 \big) + \big( 1 - w_7(X) \big) \cdot \big((w_2(X) - w_0(X) \big) \cdot w_8(X) - w_3(X) + w_1(X) \big) = 0$
4. $w_0(X) + w_2(X) + w_4(X) - w_8(X)^2 = 0$
5. $w_8(X) \cdot \big( w_0(X) - w_4(X)\big) - w_1(X) - w_4(X) = 0$
6. $\big( w_3(X) - w_1(X) \big) \cdot \big( w_7(X) - w_6(X) \big) = 0$
7. $( w_3(X) - w_1(X) ) \cdot w_9(X) - w_6(X) = 0$

`ExamplePairs`:

1. $w_0(X) - w_1(X) = 0$
2. $w_2(X) - w_3(X) = 0$
3. $w_4(X) - w_5(X) = 0$

`ExampleTriples`:

1. $w_0(X) \cdot w_1(X) \cdot w_2(X) = 0$
2. $w_3(X) \cdot w_4(X) \cdot w_5(X) = 0$
3. $w_6(X) \cdot w_7(X) \cdot w_8(X) = 0$
4. $w_9(X) \cdot w_{10}(X) \cdot w_{11}(X) = 0$
5. $w_{12}(X) \cdot w_{13}(X) \cdot w_{14}(X) = 0$

These are the $16$ constraints that will need to be satisfied by a correct
witness for the relation. We already know how to check many equations at once
(combining them with powers of alpha), and how to check that the above holds for
the full domain $\mathbb{G}$ (by providing the quotient polynomial of the huge
equation after dividing by the vanishing polynomial on $\mathbb{G}$). All
there's left to do is making a correspondence between the constraints that need
to be satisfied, and the particular row in the execution trace to which they
apply. This implies, that before even aggregating the $16$ constraints into a
single one, we need to impose this restriction.

In `proof-systems`, we represent this restriction with the `GateType` selector.
In particular, we would multiply each of the constraints above by the `Expr`
terms: `Index(GateType::`YourType`)`, which will be transformed (again) into
mutually exclusive selector polynomials. This means, that each row can only have
one of these polynomials being nonzero (equal to $1$), whereas the evaluation of
all of the other selector polynomials for the given row should be $0$. These
polynomials are known by the verifier, who could check that this is indeed the
case.

But what will these polynomials look like? I am sure the above paragraph is
familiar for you already. Once again, we will be able to build them using
interpolation with our $4$ Lagrangian terms for $\mathbb{G}$. In our example:
$\text{generic}(X)$ will equal $1$ when $X=g^0$ and $0$ otherwise;
$\text{add}(X)$ will equal $1$ when $X=g^1$ and $0$ otherwise; $\text{pairs}(X)$
will equal $1$ when $X=g^2$ and $0$ otherwise; and $\text{triples}(X)$ will
equal $1$ when $X=g^3$ and $0$ otherwise. These polynomials are, in fact, a
description of the circuit.

Note that we managed to make constraints for different gates already independent
from each other (thanks to the mutually exclusivity). Nonetheless, granting
independence within the gate is still needed. Here's where we will be using the
powers of alpha: within a gate the powers cannot be repeated, but they can be
reused among gates. Then, we will need $7$ different powers of alpha for this
stage of the protocol, as this is the largest number of different constraints
within the same gate.

Putting all of the above together, this means that our LONG and single
constraint will look like:

$ \text{gates}(X) = $

$\quad \text{generic}(X) \cdot $

$\qquad \alpha^0 \cdot \Big( w_0(X)\cdot c_l + w_1(X) \cdot c_r + w_2(X) \cdot c_o + w_0(X) \cdot w_1(X) \cdot c_m + c_c \Big)$

$ \quad + \text{add}(X) \cdot \huge($

$\qquad \alpha^0 \cdot \Big( w_{10}(X) \cdot \big( w_2(X) - w_0(X)\big) - \big( 1 -  w_7(X)\big) \Big )$

$\qquad + \alpha^1 \cdot \Big( w_7(X) \cdot ( w_2(X) - w_0(X) ) \Big)$

$\qquad + \alpha^2 \cdot \Big( w_7(X) \cdot \big( 2 \cdot w_8(X) \cdot w_1(X) - 3 \cdot w_0(X)^2 \big) + \big( 1 - w_7(X) \big) \cdot \big((w_2(X) - w_0(X) \big) \cdot w_8(X) - w_3(X) + w_1(X) \big) \Big)$

$\qquad + \alpha^3 \cdot \Big( w_0(X) + w_2(X) + w_4(X) - w_8(X)^2 \Big)$

$\qquad + \alpha^4 \cdot \Big ( w_8(X) \cdot \big( w_0(X) - w_4(X)\big) - w_1(X) - w_4(X) \Big)$

$\qquad + \alpha^5 \cdot \Big ( \big( w_3(X) - w_1(X) \big) \cdot \big( w_7(X) - w_6(X) \big) \Big)$

$\qquad + \alpha^6 \cdot \Big( ( w_3(X) - w_1(X) ) \cdot w_9(X) - w_6(X) \Big) \huge)$

$\quad + \text{pairs}(X) \cdot \Big($

$\qquad \alpha^0 \cdot \big( w_0(X) - w_1(X) \big)$

$\qquad + \alpha^1 \cdot \big( w_2(X) - w_3(X) \big)$

$\qquad + \alpha^2 \cdot \big( w_4(X) - w_5(X) \big) \Big)$

$\quad + \text{triples}(X) \cdot \Big($

$\qquad \alpha^0 \cdot \big( w_0(X) \cdot w_1(X) \cdot w_2(X) \big)$

$\qquad + \alpha^1 \cdot \big( w_3(X) \cdot w_4(X) \cdot w_5(X) \big)$

$\qquad + \alpha^2 \cdot \big( w_6(X) \cdot w_7(X) \cdot w_8(X) \big)$

$\qquad + \alpha^3 \cdot \big( w_9(X) \cdot w_{10}(X) \cdot w_{11}(X) \big)$

$\qquad + \alpha^4 \cdot \big( w_{12}(X) \cdot w_{13}(X) \cdot w_{14}(X) \big) \Big)$

Finally, providing $q(X) = \text{gates}(X)/v_{\mathbb{G}}(X)$ and performing the
check on a random $X\in\mathbb{F}$ \ $\mathbb{G}$ would give the verifier the
assurance of the following:

_The prover knows a polynomial_ $\text{gates}(X)$ _that equals zero on any_
$x\in\{1,g,g^2,g^3\}$.

Nonetheless, it would still remain to verify that $\text{gates}(X)$ actually
corresponds to the encoding of the actual constraints. Meaning, checking that
this polynomial encodes the column witnesses, and the agreed circuit. So instead
of providing just $\text{gates}(X)$ (actually, a commitment to it), the prover
can send commitments to each of the $15$ witness polynomials, so that the
verifier can reconstruct the huge constraint using the encodings of the circuit
(which is known ahead).

<!--- TO-DO (anais): check how the verifier merges both things, as they are quite intertwined and the degrees of the products may could too large for pairings? --->
