# A More Efficient Approach to Zero Knowledge for PLONK

In PLONK (considered as an interactive oracle proof), the prover sends the
verifier several polynomials. They are evaluated at some $k$ points during the
course of the protocol. Of course, if we want zero-knowledge, we would require
that those evaluations do not reveal anything about the proof's underlying
witness.

PLONK as described
<a href="https://eprint.iacr.org/2019/953" target="_blank" rel="noopener">here</a>
achieves
<a href="https://minaprotocol.com/blog/zero-knowledge-proofs-an-intuitive-explanation">zero
knowledge</a> by multiplying the polynomials with a small degree polynomial of
random coefficients. When PLONK is instantiated with a discrete-log base
<a href="https://eprint.iacr.org/2016/263" target="_blank" rel="noopener">Bootle
et al type</a> polynomial commitment scheme, the polynomial degrees must be
padded to the nearest power of two. As a result, since several of the
polynomials in PLONK already have degree equal to a power of two before the
zero-knowledge masking, the multiplication with a random polynomial pushes the
degree to the next power of two, which hurts efficiency. In order to avoid it,
we propose an alternative method of achieving zero knowledge.

## Zero Knowledge for the Column Polynomials

Let $w$ be the number of rows in a PLONK constraint system. For a typical
real-world circuit, $w$ will not be equal to a power of two.

Let the witness elements from one column be $s_1, s_2, \ldots, s_w$. Let $n$ be
the closest power of two to $w$ such that $n \geq w$. Let $\mathbb{F}$ be the
field that witness elements belong to.

Now, in vanilla PLONK, we pad the $s_i$ with $n - w$ elements, interpolate the
polynomial over a domain of size $n$, scale it by a low degree random
polynomial, and commit to the resulting polynomial. We want to avoid increasing
the degree with the scaling by a low degree polynomial, so consider the
following procedure.

**Procedure.** Sample $k$ elements uniformly from $\mathbb{F}$:
$r_{w+1}, \ldots, r_{w+k}$. Append them to the tuple of witness elements and
then pad the remaining $n - (w+k)$ places as zeroes. The resulting tuple is
interpolated as the witness polynomial. This approach ensures zero knowledge for
the witness polynomials as established by Lemma 1.

**Lemma 1.** Let $H \subset \mathbb{F}$ be a domain of size $n$. Let
$s_1, s_2, \ldots, s_w\in \mathbb{F}$. Let $r_{w+1}, \ldots, r_{w+k}$ be $k$
uniformly and independently random elements in $\mathbb{F}.$ Let $\mathbf{v}$ be
the $n$-tuple
$\mathbf{v} = (s_1, s_2, \ldots, s_w, r_{w+1}, \ldots, r_{w+k}, 0,\ldots_{\text{n - (w+k) times}})$.
Let $f(X)$ be an interpolation polynomial of degree $n-1$ such that
$f(h_i) = v_i$, where $h_i \in H$. Let $c_1, \ldots, c_k$ be any elements in
$\mathbb{F}$ such that $c_i \neq v_j$ for every $i,j$. Then,
$(f(c_1), \ldots, f(c_k))$ is distributed uniformly at random in $\mathbb{F}^k$.

**Proof sketch.** Recall that the interpolation polynomial is

$$
f(X) = \sum_{j = 1}^n \prod_{k \neq j} \frac{(X-h_k)}{(h_j-h_k)} v_j
$$

With $V_{w+1}, \ldots, V_{w+k}$ as random variables, we have,
$f(X) = a_{w+1} V_{w+1} + a_{w+2} V_{w+2} + \ldots + a_{w+k} V_{w+k} + a$ for
some constant field elements $a, a_{w+1}, \ldots, a_{w+k}$. Therefore, assigning
random values to $V_{w+1}, \ldots, V_{w+k}$ will give $k$ degrees of freedom
that will let $(f(c_1), \ldots, f(c_k))$ to be distributed uniformly at random
in $\mathbb{F}^k$.

## Zero Knowledge for the Permutation Polynomial

The other polynomial in PLONK for which we need zero-knowledge is the
"permutation polynomial" $z$. The idea here is to set the last $k$ evaluations
to be uniformly random elements $t_1, \ldots, t_k$ in $\mathbb{F}$. Then, we'll
modify the verification equation to not check for those values to satisfy the
permutation property.

**Modified permutation polynomial.** Specifically, set $z(X)$ as follows.

$$
z(X) = L_1(X) + \sum_{i = 1}^{\blue{n-k-2}} \left(L_{i+1} \prod_{j=1}^i \mathsf{frac}_{i,j} \right) + \blue{t_1 L_{n-k}(X) + \ldots + t_k L_{n}(X) }
$$

From Lemma 1, the above $z(X)$ has the desired zero knowledge property when $k$
evaluations are revealed. However, we need to modify the other parts of the
protocol so that the last $k$ elements are not subject to the permutation
evaluation, since they will no longer satisfy the permutation check.
Specifically, we will need to modify the permutation polynomial to disregard
those random elements, as follows.

$$
\begin{aligned}  & t(X) = \\
  & \Big(a(X)b(X)q_M(X) + a(X)q_L(X) + b(X)q_R(X) + c(X)q_O(X) + PI(X) + q_C(X)\Big) \frac{1}{z_H(X)} \\
  &+ \Big((a(X) + \beta X + \gamma)(b(X) + \beta k_1 X + \gamma)(c(X) + \beta k_2X + \gamma)z(X)\\
  &\qquad\qquad\qquad\times{\blue{(X-h_{n-k}) \ldots (X-h_{n-1})(X-h_n)}} \Big) \frac{\alpha}{z_{H}(X)} \\
  & - \Big((a(X) + \beta S_{\sigma1}(X) + \gamma)(b(X) + \beta S_{\sigma2}(X) + \gamma)(c(X) + \beta S_{\sigma3}(X) + \gamma)z(X\omega)\\
  &\qquad\qquad\qquad\times{\blue{(X-h_{n-k}) \ldots (X-h_{n-1})(X-h_n)}}\Big) \frac{\alpha}{z_{H}(X)} \\
  & + \Big(z(X)-1\Big)\cdot L_1(X) \frac{\alpha^2}{z_H(X)} \\
  & + \blue{\Big(z(X)-1\Big)\cdot L_{n-k}(X) \frac{\alpha^3}{z_H(X)} }  \end{aligned}
$$

**Modified permutation checks.** To recall, the permutation check was originally
as follows. For all $h \in H$,

- $L_1(h)(Z(h) - 1) = 0$
- $$
  Z(h)[(a(h) + \beta h + \gamma)(b(h) + \beta k_1 h + \gamma)(c(h) + \beta k_2 h + \gamma)] \\
  = Z(\omega h)[(a(h) + \beta S_{\sigma1}(h) + \gamma)(b(h) + \beta S_{\sigma2}(h) + \gamma)(c(h) + \beta S_{\sigma3}(h) + \gamma)]
  $$

The modified permutation checks that ensures that the check is performed only on
all the values except the last $k$ elements in the witness polynomials are as
follows.

- For all $h \in H$, $L_1(h)(Z(h) - 1) = 0$
- For all $h \in \blue{H\setminus \{h_{n-k}, \ldots, h_n\}}$,

  $$
  \begin{aligned}  & Z(h)[(a(h) + \beta h + \gamma)(b(h) + \beta k_1 h + \gamma)(c(h) + \beta k_2 h + \gamma)] \\
  &= Z(\omega h)[(a(h) + \beta S_{\sigma1}(h) + \gamma)(b(h) + \beta S_{\sigma2}(h) + \gamma)(c(h) + \beta S_{\sigma3}(h) + \gamma)]  \end{aligned}
  $$

- For all $h \in H$, $L_{n-k}(h)(Z(h) - 1) = 0$

In the modified permutation polynomial above, the multiple
$(X-h_{n-k}) \ldots (X-h_{n-1})(X-h_n)$ ensures that the permutation check is
performed only on all the values except the last $k$ elements in the witness
polynomials.
