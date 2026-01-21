# Rings

A ring is like a field, but where elements may not be invertible. Basically,
it's a structure where we can

- add

- multiply

- subtract

but not necessarily divide. If you know what polynomials are already, you can
think of it as the minimal necessary structure for polynomials to make sense.
That is, if $R$ is a ring, then we can define the set of polynomials $R[x]$
(basically arithmetic expressions in the variable $x$) and think of any
polynomial $f \in R[x]$ giving rise to a function $R \to R$ defined by
substituting in for $x$ in $f$ and computing using $+$ and $\cdot$ as defined in
$R$.

So, in full, a ring $R$ is a set equipped with

- $(+) \colon R \times R \to R$

- $(\cdot) \colon R \times R \to R$

- $(-) \colon R \to R$

- $0 \in R$

- $1 \in R$

such that

- $(+, 0, -)$ gives the structure of an abelian group

- $(\cdot)$ is associative and commutative with identity $1$

- $+$ distributes over $\cdot$. I.e., $x \cdot (y + z) = x\cdot y + x \cdot z$
  for all $x, y, z$.
