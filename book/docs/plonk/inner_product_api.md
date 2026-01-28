# Different functionalities

There's a number of useful stuff that we can do on top of a bootleproof-style
polynomial commitment. I'll briefly list them here.

### Enforcing an upperbound on the polynomial degree

Imagine that you want to enforce a maximum degree on a committed polynomial. You
can do that by asking the prover to shift the coefficients of the polynomial to
the right, so much that it becomes impossible to fit them if the polynomial were
to be more than the maximum degree we wanted to enforce. This is equivalent to
the following:

$$ \text{right_shift}(f) = x^{n-max} f $$

When the verifier verifies the opening, they will have to right shift the
received evaluation in the same way.

$$ \text{right_shift}(f(z)) = z^{n-max} f(z) $$

### Aggregating opening proofs for several polynomials

Insight:

$$
\langle \vec{f} + v \cdot \vec{g}, \vec{x}\rangle = f(x) + v \cdot g(x)
$$

### Aggregating opening proofs for several evaluations

Insight:

$$
\langle \vec{f}, \vec{x_1} + u \cdot \vec{x_2}\rangle = f(x_1) + u \cdot f(x_2)
$$

### Double aggregation

Insight:

$$
\langle \vec{f} + v \cdot \vec{g}, \vec{x_1} + u \cdot \vec{x_2} \rangle = f(x_1) + v \cdot g(x_1) + u \cdot (f(x_2) + v \cdot g(x_2))
$$

Note that this kind of aggregation forces us to provide all combinations of
evaluations, some of which might not be needed (for example, $f(x_2)$).

### Splitting a polynomial

If a polynomial is too large to fit in one SRS, you can split it in chunks of
size at most $n$

### Proof of correct commitment to a polynomial

That is useful in HALO. Problem statement: given a commitment $A$, and a
polynomial $f$, prove to me that the $A = com(f)$. The proof is simple:

- generate a random point $s$
- evaluate $f$ at $s$, $f(s) = y$
- ask for an evaluation proof of $A$ on $s$. If it evaluates to $y$ as well then
  $A$ is a commitment to $f$ with overwhelming probability
