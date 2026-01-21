# Understanding the implementation of the $f(\zeta) = Z_H(\zeta) t(\zeta)$ check

Unlike the latest version of vanilla $\plonk$ that implements the final check
using a polynomial opening (via Maller's optimization), we implement it
manually. (That is to say, Izaak implemented Maller's optimization for 5-wires.)

But the check is not exactly $f(\zeta) = Z_H(\zeta) t(\zeta)$. This note
describes how and why the implementation deviates a little.

## What's f and what's missing in the final equation?

If you look at how the evaluation of $f(z)$ is computed on the prover side (or
the commitment of $f$ is computed on the verifier side), you can see that f is
missing two things:

- the public input part
- some terms in the permutation

What is it missing in the permutation part? Let's look more closely. This is
what we have:

$$
\begin{align}
-1\, \cdot\, &z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
     \cdot\, &(w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \\
     \cdot\, &(w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \\
     \cdot\, &(w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \\
     \cdot\, &(w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \\
     \cdot\, &(w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \\
     \cdot\, &(w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \\
     \cdot\, &\beta \cdot \sigma[6](x)
\end{align}
$$

In comparison, here is the list of the stuff we needed to have:

1. the two sides of the coin:
   $$
   \begin{align}
        z(\zeta)\, \cdot\, &\mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
                   \cdot\, &(w[0](\zeta) + \beta \cdot \mathsf{shift}[0](\zeta) + \gamma) \\
                   \cdot\, &(w[1](\zeta) + \beta \cdot \mathsf{shift}[1](\zeta) + \gamma) \\
                   \cdot\, &(w[2](\zeta) + \beta \cdot \mathsf{shift}[2](\zeta) + \gamma) \\
                   \cdot\, &(w[3](\zeta) + \beta \cdot \mathsf{shift}[3](\zeta) + \gamma) \\
                   \cdot\, &(w[4](\zeta) + \beta \cdot \mathsf{shift}[4](\zeta) + \gamma) \\
                   \cdot\, &(w[5](\zeta) + \beta \cdot \mathsf{shift}[5](\zeta) + \gamma) \\
                   \cdot\, &(w[6](\zeta) + \beta \cdot \mathsf{shift}[6](\zeta) + \gamma)
   \end{align}
   $$
   with $\mathsf{shift}[0] = 1$
2. and
   $$
   \begin{align}
   -1\, \cdot\, &z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
        \cdot\, &(w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \\
        \cdot\, &(w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \\
        \cdot\, &(w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \\
        \cdot\, &(w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \\
        \cdot\, &(w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \\
        \cdot\, &(w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \\
        \cdot\, &(w[6](\zeta) + \beta \cdot \sigma[6](\zeta) + \gamma)
   \end{align}
   $$
3. the initialization:
   $$(z(\zeta) - 1) \cdot L_1(\zeta) \cdot \alpha^{\mathsf{PERM1}}$$
4. and the end of the accumulator:
   $$(z(\zeta) - 1) \cdot L_{n-k}(\zeta) \cdot \alpha^{\mathsf{PERM2}}$$

You can read more about why it looks like that in
[this post](https://minaprotocol.com/blog/a-more-efficient-approach-to-zero-knowledge-for-plonk).

We can see clearly that the permutation stuff we have in f is clearly lacking.
It's just the subtraction part (equation 2), and even that is missing some
terms. It is missing exactly this:

$$
\begin{align}
    -1\ \cdot\, &z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}}  \\
        \cdot\, &(w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma)  \\
        \cdot\, &(w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma)  \\
        \cdot\, &(w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma)  \\
        \cdot\, &(w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma)  \\
        \cdot\, &(w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma)  \\
        \cdot\, &(w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma)  \\
        \cdot\, &(w[6](\zeta) + \gamma)
\end{align}
$$

So at the end, when we have to check for the identity
$f(\zeta) = Z_H(\zeta) t(\zeta)$ we'll actually have to check something like
this (I colored the missing parts on the left-hand side of the equation):

$$
\begin{align}
f(\zeta) &+ \color{darkgreen}{\mathsf{pub}(\zeta)} \\
& \color{darkred}{+ z(\zeta) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}}} \\
& \qquad \color{darkred}{\cdot (w[0](\zeta) + \beta \zeta + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[1](\zeta) + \beta \cdot \mathsf{shift}[0](\zeta) + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[2](\zeta) + \beta \cdot \mathsf{shift}[1](\zeta) + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[3](\zeta) + \beta \cdot \mathsf{shift}[2](\zeta) + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[4](\zeta) + \beta \cdot \mathsf{shift}[3](\zeta) + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[5](\zeta) + \beta \cdot \mathsf{shift}[4](\zeta) + \gamma)} \\
& \qquad \color{darkred}{\cdot (w[6](\zeta) + \beta \cdot \mathsf{shift}[5](\zeta) + \gamma)} \\
& \color{blue}{- z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \cdot} \\
& \qquad \color{blue}{\cdot (w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \cdot} \\
& \qquad \color{blue}{\cdot (w[6](\zeta) + \gamma)} \\
& \color{purple}{+ (z(\zeta) - 1) \cdot L_1(\zeta) \cdot \alpha^{\mathsf{PERM1}}} \\
& \color{darkblue}{+ (z(\zeta) - 1) \cdot L_{n-k}(\zeta) \cdot \alpha^{\mathsf{PERM2}}} \\
& = t(\zeta)(\zeta^n - 1)
\end{align}
$$

This is not exactly what happens in the code. But if we move things around a
bit, we end up with what's implemented. I highlight what changes in each steps.
First, we just move things around:

$$
\begin{align}
f(\zeta) &+ \mathsf{pub}(\zeta) \\
 &+ z(\zeta) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
& \qquad \cdot (w[0](\zeta) + \beta \cdot \mathsf{shift}[0] \zeta + \gamma)  \\
& \qquad \cdot (w[1](\zeta) + \beta \cdot \mathsf{shift}[1] \zeta + \gamma)  \\
& \qquad \cdot (w[2](\zeta) + \beta \cdot \mathsf{shift}[2] \zeta + \gamma)  \\
& \qquad \cdot (w[3](\zeta) + \beta \cdot \mathsf{shift}[3] \zeta + \gamma)  \\
& \qquad \cdot (w[4](\zeta) + \beta \cdot \mathsf{shift}[4] \zeta + \gamma)  \\
& \qquad \cdot (w[5](\zeta) + \beta \cdot \mathsf{shift}[5] \zeta + \gamma)  \\
& \qquad \cdot (w[6](\zeta) + \beta \cdot \mathsf{shift}[6] \zeta + \gamma) \\
 &- z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \cdot \\
& \qquad \cdot (w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \\
& \qquad \cdot (w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \\
& \qquad \cdot (w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \\
& \qquad \cdot (w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \\
& \qquad \cdot (w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \\
& \qquad \cdot (w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \\
& \qquad \cdot (w[6](\zeta) + \gamma) \\
&\color{darkred}{- t(\zeta)(\zeta^n - 1)} \\
 &= \color{darkred}{(1 - z(\zeta)) L_1(\zeta) \alpha^{\mathsf{PERM1}}} \\
 & \qquad \color{darkred}{+ (1 - z(\zeta)) L_{n-k}(\zeta) \alpha^{\mathsf{PERM2}}} \\
\end{align}
$$

here are the actual lagrange basis calculated with the
[formula here](../plonk/lagrange.md), oh and we actually use $L_0$ in the code,
not $L_1$, so let's change that as well:

$$
\begin{align}
f(\zeta) + &\mathsf{pub}(\zeta) \\
+ & z(\zeta) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
& \quad \cdot (w[0](\zeta) + \beta \cdot \mathsf{shift}[0] \zeta + \gamma) \\
& \quad \cdot (w[1](\zeta) + \beta \cdot \mathsf{shift}[1] \zeta + \gamma) \\
& \quad \cdot (w[2](\zeta) + \beta \cdot \mathsf{shift}[2] \zeta + \gamma) \\
& \quad \cdot (w[3](\zeta) + \beta \cdot \mathsf{shift}[3] \zeta + \gamma) \\
& \quad \cdot (w[4](\zeta) + \beta \cdot \mathsf{shift}[4] \zeta + \gamma) \\
& \quad \cdot (w[5](\zeta) + \beta \cdot \mathsf{shift}[5] \zeta + \gamma) \\
& \quad \cdot (w[6](\zeta) + \beta \cdot \mathsf{shift}[6] \zeta + \gamma) + \\
- & z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
& \quad \cdot (w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \\
& \quad \cdot (w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \\
& \quad \cdot (w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \\
& \quad \cdot (w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \\
& \quad \cdot (w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \\
& \quad \cdot (w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \\
& \quad \cdot (w[6](\zeta) + \gamma) + \\
- & t(\zeta)(\zeta^n - 1) \\
= & \color{darkred}{(1 - z(\zeta))[\frac{(\zeta^n - 1)}{n(\zeta - 1)} \alpha^{\mathsf{PERM1}} + \frac{\omega^{n-k}(\zeta^n - 1)}{n(\zeta - \omega^{n-k})} \alpha^{\mathsf{PERM2}}]}
\end{align}
$$

finally we extract some terms from the lagrange basis:

$$
\begin{align}
& \color{darkred}{[} \\
&  f(\zeta) + \mathsf{pub}(\zeta) \\
&  + z(\zeta) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}}  \\
&  \qquad \cdot (w[0](\zeta) + \beta \cdot \mathsf{shift}[0] \zeta + \gamma) \\
&  \qquad \cdot (w[1](\zeta) + \beta \cdot \mathsf{shift}[1] \zeta + \gamma) \\
&  \qquad \cdot (w[2](\zeta) + \beta \cdot \mathsf{shift}[2] \zeta + \gamma) \\
&  \qquad \cdot (w[3](\zeta) + \beta \cdot \mathsf{shift}[3] \zeta + \gamma) \\
&  \qquad \cdot (w[4](\zeta) + \beta \cdot \mathsf{shift}[4] \zeta + \gamma) \\
&  \qquad \cdot (w[5](\zeta) + \beta \cdot \mathsf{shift}[5] \zeta + \gamma) \\
&  \qquad \cdot (w[6](\zeta) + \beta \cdot \mathsf{shift}[6] \zeta + \gamma) + \\
&  - z(\zeta \omega) \cdot \mathsf{zkpm}(\zeta) \cdot \alpha^{\mathsf{PERM0}} \\
&  \qquad \cdot (w[0](\zeta) + \beta \cdot \sigma[0](\zeta) + \gamma) \\
&  \qquad \cdot (w[1](\zeta) + \beta \cdot \sigma[1](\zeta) + \gamma) \\
&  \qquad \cdot (w[2](\zeta) + \beta \cdot \sigma[2](\zeta) + \gamma) \\
&  \qquad \cdot (w[3](\zeta) + \beta \cdot \sigma[3](\zeta) + \gamma) \\
&  \qquad \cdot (w[4](\zeta) + \beta \cdot \sigma[4](\zeta) + \gamma) \\
&  \qquad \cdot (w[5](\zeta) + \beta \cdot \sigma[5](\zeta) + \gamma) \\
&  \qquad \cdot (w[6](\zeta) + \gamma) \\
&  - t(\zeta)(\zeta^n - 1) \\
& \color{darkred}{] \cdot (\zeta - 1)(\zeta - \omega^{n-k})} & \\
& = \color{darkred}{(1 - z(\zeta))\Bigg[\frac{(\zeta^n - 1)(\zeta - \omega^{n-k})}{n} \alpha^{\mathsf{PERM1}} + \frac{\omega^{n-k}(\zeta^n - 1)(\zeta - 1)}{n} \alpha^{\mathsf{PERM2}}\Bigg]}
\end{align}
$$

with
$\alpha^{\mathsf{PERM0}} = \alpha^{17}, \alpha^{\mathsf{PERM1}} = \alpha^{18}, \alpha^{\mathsf{PERM2}} = \alpha^{19}$

Why do we do things this way? Most likely to reduce

Also, about the code:

- the division by $n$ in the $\alpha^{\mathsf{PERM1}}$ and the
  $\alpha^{\mathsf{PERM2}}$ terms is missing (why?)
- the multiplication by $w^{n-k}$ in the $\alpha^{\mathsf{PERM2}}$ term is
  missing (why?)

As these terms are constants, and do not prevent the division by $Z_H$ to form
$t$, $t$ also omits them. In other word, they cancel one another.

## What about $t$?

In `verifier.rs` you can see the following code (cleaned to remove anything not
important)

```rust=
// compute the witness polynomials $w_0, \cdots, w_14$ and the permutation polynomial $z$ in evaluation forms on different domains
let lagrange = index.cs.evaluate(&w, &z);

// compute parts of the permutation stuff that is included in t
let (perm, bnd) = index.cs.perm_quot(&lagrange, &oracles, &z, &alpha[range::PERM])?;

// divide contributions with vanishing polynomial
let (mut t, res) = (perm + some_other_stuff).divide_by_vanishing_poly()

// add the other permutation stuff
t += &bnd;

// t is evaluated at zeta and sent...
```

Notice that **`bnd` is not divided by the vanishing polynomial**. Also what's
`perm`? Let's answer the latter TESTREMOVEME:

$$
\begin{align}
\mathsf{perm}(x) =\ & a^{\mathsf{PERM0}} \cdot \mathsf{zkpl}(x) \cdot [ \\
    & z(x) \cdot (w[0](x) + \gamma + x \cdot \beta \cdot \mathsf{shift}[0])  \\
    & \qquad \cdot (w[1](x) + \gamma + x \cdot \beta \cdot \mathsf{shift}[1]) \cdot \ldots \\
  - &z(x \cdot w) \cdot (w[0](x) + \gamma + \sigma[0] \cdot \beta) \\
    & \qquad \quad \ \ \cdot (w[1](x) + \gamma + \sigma[1] \cdot \beta) \cdot \ldots \\
    &]
\end{align}
$$

and `bnd` is:

$$
\mathsf{bnd}(x) =
    a^{\mathsf{PERM1}} \cdot \frac{z(x) - 1}{x - 1}
    +
    a^{\mathsf{PERM2}} \cdot \frac{z(x) - 1}{x - \mathsf{sid}[n-k]}
$$

you can see that some terms are missing in `bnd`, specifically the numerator
$x^n - 1$. Well, it would have been cancelled by the division by the vanishing
polynomial, and this is the reason why we didn't divide that term by
$Z_H(x) = x^n - 1$.

Also, note that the same constant terms that were missing in $f$ are missing in
$t$.
