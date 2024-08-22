## Sympolyc: symbolic interpreter of multivariate polynomials


This library aims to provide algorithms and different representations to
manipulate multivariate polynomials.

## Notation

$\mathbb{F}^{\le d}[X_1, \cdots, X_{N}]$ is the vector space over the finite
field $\mathbb{F}$ of multivariate polynomials with $N$ variables and of maximum
degree $d$.

For instance, for multivariate polynomials with two variables, and maximum
degree 2, the set is
```math
\mathbb{F}^{\le 2}[X_{1}, X_{2}] = \left\{ a_{0} + a_{1} X_{1} + a_{2} X_{2} + a_{3} X_{1} X_{2} + a_{4} X_{1}^2 + a_{5} X_{2}^2 \, | \, a_{i} \in \mathbb{F} \right\}
```

The normal form of a multivariate polynomials is the multi-variate polynomials
whose monomials are all different, i.e. the coefficients are in the "canonical"
(sic) base $\{ \prod_{k = 1}^{N} X_{i_{1}}^{n_{i_{1}}} \cdots X_{i_{k}}^{n_{k}}
\}$ where $\sum_{k = 1}^{N} n_{i_{k}} \le d$.

For instance, the canonical base of $\mathbb{F}^{\le 2}[X_{1}, X_{2}]$ is the set $\{ 1, X_{1}, X_{2}, X_{1} X_{2}, X_{1}^2, X_{2}^2 \}$

Examples:

- $X_{1} + X_{2}$ is in normal form
- $X_{1} + 42 X_{1}$ is not in normal form
- $X_{1} (X_{1} + X_{2})$ is not in normal form
- $X_{1}^2 + X_{1} X_{2}$ is in normal form

## Algorithms

First, we start by attributing a different prime number for each variable.
For instance, for $\mathbb{F}^{\le 2}[X_{1}, X_{2}]$, we assign $X_{1}$ to $2$
and $X_{2}$ to $3$.
From there, we note $X_{1} X_{2}$ as the value $6$, $X_{1}^2$ as $4$, $X_{2}^2$
as 9. The constant is $1$.

From there, we represent our polynomial coefficients in a sparse list. Some
cells, noted `NA`, won't be used for certain vector spaces.

For instance, $X_{1} + X_{2}$ will be represented as:
```
[0,   1,   1,   0,    0,   0,    0,    0,    0]
 |    |    |    |     |    |     |     |     |
 1    2    3    4     5    6     7     8     9
 |    |    |    |     |    |     |     |     |
 cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
```

and the polynomial $42 X_{1} + 3 X_{1} X_{2} + 14 X_{2}^2$ will be represented
as

```
[0,  42,   1,   0,    0,   3,    0,    0,    14]
 |    |    |    |     |    |     |     |     |
 1    2    3    4     5    6     7     8     9
 |    |    |    |     |    |     |     |     |
 cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2
```

Adding two polynomials in this base is pretty straightforward: we simply add the
coefficients of the two lists.

Multiplication is not more complicated.
To compute the result of $P_{1} * P_{2}$, the value of index $i$ will be the sum
of the decompositions.

For instance, if we take $P_{1}(X_{1}) = 2 X_{1} + X_{2}$ and $P_{2}(X_{1},
X_{2}) = X_{2} + 3$, the expected product is
$P_{3}(X_{1}, X_{2}) = (2 X_{1} + X_{2}) * (X_{2} + 3) = 2 X_{1} X_{2} + 6
X_{1} + 3 X_{2} + X_{2}^2$

Given in the representation above, we have:

```
For P_{1}:

[0,   2,   1,   0,    0,   0,    0,    0,    0]
 |    |    |    |     |    |     |     |     |
 1    2    3    4     5    6     7     8     9
 |    |    |    |     |    |     |     |     |
 cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2

```

```
For P_{2}:

[3,   0,   1,   0,    0,   0,    0,    0,    0]
 |    |    |    |     |    |     |     |     |
 1    2    3    4     5    6     7     8     9
 |    |    |    |     |    |     |     |     |
 cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2

```


```
For P_{3}:

[0,   6,   3,   0,    0,   2,    0,    0,    1]
 |    |    |    |     |    |     |     |     |
 1    2    3    4     5    6     7     8     9
 |    |    |    |     |    |     |     |     |
 cst  X1  X2   X1^2   NA  X1*X2  NA   NA    X2^2

```

To compute $P_{3}$, we get iterate over an empty list of $9$ elements which will
define $P_{3}$.

For index $1$, we multiply $P_{1}[1]$ and $P_{1}[1]$.

FOr index $2$, the only way to get this index is by fetching $2$ in each list.
Therefore, we do $P_{1}[2] P_{2}[1] + P_{2}[2] * P_{1}[1] = 2 * 3 + 0 * 0 = 6$.

For index $3$, same than for $2$.

For index $4$, we have $4 = 2 * 2$, therefore, we multiply $P_{1}[2]$ and $P_{2}[2]$

For index $6$, we have $6 = 2 * 3$ and $6 = 3 * 2$, which are the prime
decompositions of $6$. Therefore we sum $P_{1}[2] * P_{2}[3]$ and $P_{2}[2] *
P_{1}[3]$.

For index $9$, we have $9 = 3 * 3$, therefore we do the same than for $4$.

This can be generalized.

The algorithm is as follow:
- for each cell $j$:
    - if $j$ is prime, compute $P_{1}[j] P_{2}[1] + P_{2}[j] P_{1}[1]$
    - else:
        - take the prime decompositions of $j$ (and their permutations).
        - for each decomposition, compute the product
        - sum


#### Other examples degree $2$ with 3 variables.

$$
\begin{align}
$\mathbb{F}^{\le 2}[X_{1}, X_{2}, X_{3}] = \{
        & \, a_{0} + \\
        & \, a_{1} X_{1} + \\
        & \, a_{2} X_{2} + \\
        & \, a_{3} X_{3} + \\
        & \, a_{4} X_{1} X_{2} + \\
        & \, a_{5} X_{2} X_{3} + \\
        & \, a_{6} X_{1} X_{3} + \\
        & \, a_{7} X_{1}^2 + \\
        & \, a_{8} X_{2}^2 + \\
        & \, a_{9} X_{3}^2 \, | \, a_{i} \in \mathbb{F}
        \}
\end{align}
$$

We assign:

- $X_{1} = 2$
- $X_{2} = 3$
- $X_{3} = 5$

And therefore, we have:
- $X_{1}^2$ = 4$
- $X_{1} X_{2}$ = 6$
- $X_{1} X_{3}$ = 10$
- $X_{2}^2 = 9$
- $X_{2} X_{3} = 15$
- $X_{3}^2 = 25$

We have an array with 25 indices, even though we need 10 elements only.

## Optimisations

- Instead of having empty cells, we can simply keep a permutation $\sigma$, and
  shift the index in the algorithms.

## Resources

This README is partially or fully imported from the document [Sympolyc -
symbolic computation on multi-variate polynomials using prime
numbers](https://hackmd.io/@dannywillems/SyHar7p5A)
