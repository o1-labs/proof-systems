# Commitments

A "commitment scheme" is a cryptographic scheme that lets us provide a
"commitment" to a given piece of data, in such a way that we can later "open"
that commitment.

I recommend checking out section 2.4.1 of David's book Real-World Cryptography.
There are two properties we typically expect of our commitment schemes:

- **Hiding.** A commitment to a piece of data should not reveal anything about
  that data.

- **Binding.** There should be no ambiguity about what data is committed to.
  That is, it should not be possible for the committer to open the commitment to
  a piece of data other than the one they originally committed to.

There are various kinds of commitments that allow opening in different ways,
revealing only part of the data, or some function of the data. Sometimes it is
even useful to elide the hiding property entirely--- so-called non-hiding
commitments.

## Simple commitments

The simplest kind of a commitment is one in which opening reveals all of the
underlying data. Let's give a simple construction of such a scheme for
committing to field elements. Suppose we have

- $\mathbb{F}_p$ a prime order field, with $p$ being rather large (say on the
  order of $2^{256}$).

- A hash function $h \colon \mathsf{List}(\mathbb{F}_p) \to \mathbb{F}_p$.

Then we define

$$
\mathsf{commit}(x, r) = h([x, r]) \\
\mathsf{open}(c) = (x, r) \\
\mathsf{verify}(c, x, r) = \mathsf{true/false} \\
$$

The argument $r$ of the $\mathsf{commit}$ function is data that must only be
known to the committer (until the commitment is opened). When a committer wants
to commit to a field element $x$, they sample a random "blinder"
$r \in \mathbb{F}_p$ and hash it together with $x$ to form the commitment.

To open the commitment $c$, they simply provide the committed value together
with the blinder. Alternatively, if the verifier already knows $x$, they can
just provide $r$, i.e. $\mathsf{open}(x,c) = r$. Finally, given the commitment
and the opening, we can verify whether the input was the value originally
committed to using the $\mathsf{verify}$ function.

If the hash function is collision-resistant, then this function is binding
(because there's no way the committer could find another preimage of
$h([x, r])$).

If the hash function is one-way, then this commitment is also hiding (assuming
$x$ is revealed only as part of the opening).

Commitments are often used in protocols between provers and verifiers. The
following illustration provides an example with a prover named Peggy and a
verifier named Victor.

$$
\begin{array}{lcll}
\textbf{Peggy} & \textbf{ } & \textbf{Victor} & ~ \\
\begin{aligned}\mathsf{\small input} \\ \mathsf{\small blinder}\end{aligned} ~\Bigg\} \rightarrow \boxed{\mathsf{\small commit}}  & \longrightarrow & \mathsf{\small commitment} & ~ \\
~ & \vdots & ~ & ~ \\
~ & ~ & ~ & ~ \\
\mathsf{\small commitment} \rightarrow  \boxed{\mathsf{\small open}} & \longrightarrow & \mathsf{\small input, blinder} & ~ \\
~ & \vdots & ~ & ~ \\
~ & ~ & \begin{aligned}\mathsf{\small commitment} \\ \mathsf{\small input} \\ \mathsf{\small blinder}\end{aligned} ~\Bigg\} \rightarrow \boxed{\mathsf{\small verify}} \rightarrow  \mathsf{\small true/false}
\end{array}
$$

Here Peggy commits to an input using a blinder, obtains the commitment and sends
it to Victor. The interlocutors continue their protocol, but eventually to
convince Victor of her claims, Peggy must send the opening proof to her earlier
commitment. Victor verifies the opening (i.e. the input and blinder) against the
commitment. If the verification fails, then Victor knows that Peggy was trying
to trick him, otherwise Victor has sufficient assurances that Peggy was telling
the truth.

## Algebraic and homomorphic commitments

Instead of a cryptographic hash function, we can use elliptic curve scalar
multiplication to construct a commitment scheme. Here scalar multiplication is
used like a one-way function based on the hardness assumption of the elliptic
curve discrete logarithm problem (ECDLP). Suppose we have

- $\mathbb{F}_p$ a prime order field, with $p$ being large (e.g. something like
  $2^{256}$).
- Publicly agreed generator point $G$ over an elliptic curve $E(\mathbb{F}_p)$
- Another publicly agreed curve point $H$ for which no one knows the discrete
  logarithm

$$
\mathsf{commit}(x, r) = xG + rH \\
\mathsf{open}(c) = (x, r)
$$

where $x \in \mathbb{F}_p$ is the value being committed to, $r \in \mathbb{F_p}$
is a random blinding factor and the commitment $c = \mathsf{commit}(x, r)$ is a
curve point.

These commitments are algebraic (i.e. they do not use a boolean-based
cryptographic hash function) and have homomorphic properties: you can add
commitments together to form another commitment of the added committed values.
For example, if you have commitments $A$ and $B$, you can perform:

$$
\begin{aligned}
A + B &= \mathsf{commit}(x_a, r_a) + \mathsf{commit}(x_b, r_b) \\
&= x_aG +r_aH + x_bG + r_bH \\
&= (x_a + x_b)G + (r_a + r_b)H \\
&= \mathsf{commit}(x_a + x_b, r_a + r_b)
\end{aligned}
$$

In other words, the sum of commitments $A$ and $B$ is equal to the commitment of
the sum of the two committed values $x_a$ and $x_b$ and blinders $r_a$ and
$r_b$. This is possible because in such a scheme scaling is commutative with
adding scalars.

> As a cryptographic primitive, the ability to find a public curve point $H$ for
> which no one knows the discrete logarithm may, at first, seem rather
> mind-blowing and powerful.
>
> Actually, it's as easy as it is awesome to find such a point--- simply perform
> rejection sampling by cryptographically hashing $G$ (or, respectively, the
> hash output), using the output as the $x$-coordinate of a candidate point on
> $E$ and checking whether it's valid. The first valid curve point obtained is
> $H$ and by the hardness assumption of the ECDLP, no one knows it.
>
> Since approximately half of the hash outputs will be valid curve points on
> $E$, sampling will terminate very quickly. Indeed, as we will see later, this
> process can be used to sample many public curve points $G_1, \ldots, G_n$ for
> which the discrete logarithms are unknown; the so-called _hash to curve_
> algorithm.

## Pedersen commitments

The homomorphic commitment $\mathsf{commit}(x, r) = xG + rH$ described above is
known as a Pedersen commitment. If you remove the $rH$ term you get a non-hiding
commitment, called a _Pedersen hash_. Both rely on the ECDLP hardness
assumption.

This means that, at least theoretically, you might be lucky (or have a quantum
computer) and figure out that $H = hG$, which would allow you to find different
values $x'$ and $h'$ to open the commitment. We say that pedersen commitments
are **computationally binding** and not unconditionally binding. For example,
you could express $c = xG + rH$ alternatively as $c = xG + rh G = (x + rh) G$
and compute a satisfying opening pair $x' = rh$ and $r' = \frac{x}{h}$.

On the other hand, Pedersen commitments are **unconditionally hiding**, as there
is no way (even with a magic computer) to reveal what $x$ is without knowing
$r$. Lack of perfect binding is the reason why most of the "proofs" we will see
later in this book are not referred to as proofs, but instead are referred to as
**arguments** of knowledge (although we may care little about this distinction).
Just remember that you need perfect binding to be called a proof.

> Interestingly, it is impossible to have a commitment scheme that has both
> perfect hiding and perfect binding.

To recap, in cryptography the following distinctions are important

- **Perfect.** The property that an algorithm is statistically sound without
  hardness assumptions, also known as unconditional or statistical soundness.

- **Computational.** The algorithm relies on a hardness assumption or
  computational limitation for soundness.

Thus, said another way, Pedersen commitments provide perfect hiding and
computational binding.

## Vector commitments

We can commit to several values $x_1, \cdots, x_n$ by sending separate Pedersen
commitments to all of these values as such:

$$
x_1 G + r_1 H, \\
\vdots \\
x_n G + r_n H \\
$$

But we can instead batch/aggregate all of these commitments together as a single
commitment:

$$
x_1 G_1 + \cdots + x_n G_n + r H
$$

with $G_1, \cdots, G_n, H$ independent bases with unknown discrete logarithms.

If you represent $x$s and the $G$s as two vectors $\vec{x} = (x_1, \cdots, x_n)$
and $\vec{G} = (G_1, \cdots, G_n)$, we can quickly write the previous statement
as an inner product

$$
\vec{x}\vec{G} + rH
$$

> Vector commitments (sometimes referred to as multi-commitments) are a powerful
> construction because an arbitrarily large vector can be committed with a
> single curve point.

The naive approach to constructing an opening proof for a length $n$ vector
commitment has size $O(n)$. It is simply the tuple $(x_1, \ldots, x_n, r)$. As
we will see later, opening proofs for vector commitments is an interesting topic
and there is a much more efficient algorithm.

## Polynomial commitments

To construct SNARKs we use polynomial commitments. A **polynomial commitment
scheme** for a field $F$ (or it could even be a ring) is a way of committing to
a polynomial $f \in F[x]$ to get a commitment $c$, in such a way that for any
$\alpha \in F$, you can provide $y = f(\alpha)$, along with an "opening proof"
$\pi$ that proves that the polynomial committed to in $c$ equals $y$ when
evaluated at $\alpha$.

In other words, it is a type of commitment $C$, a type of randomness $R$, a type
of opening proof $P$ along with algorithms

$$
\mathsf{commit} \colon F[x] \times R \to C \\
\mathsf{open} \colon C \times F \times (F[x] \times R) \to F \times P \\
\mathsf{verify} \colon C \times (F \times P) \to \mathsf{Bool}
$$

such that for any $f \in F[x],\; r \in R,\; \alpha \in F$ , we have

$$
c := \mathsf{commit}(f, r) \\
\mathsf{verify}(c, \mathsf{open}(c, \alpha, (f, r))) = \mathsf{true}
$$

and if $b \neq f(\alpha)$ then it is not possible to compute $\pi \in P$ such
that

$$
\mathsf{verify}(c, (b, \pi)) = \mathsf{true}
$$

In other words, if $b \neq f(\alpha)$ then every $\pi$ which is feasible to
compute results in $\mathsf{verify}(c, (b, \pi)) = \mathsf{false}$.

> One thing that's pretty cool is that because polynomial commitment schemes let
> you construct zk-SNARKs, polynomial commitment schemes imply commitment
> schemes with arbitrary opening functionality. TODO

### Constructing polynomial commitment schemes

All known constructions of polynomial commitment schemes are a bit complicated.
The easiest to describe is called the Kate (pronounced "kah-TAY") scheme, also
known as "KZG". It requires a "prime-order group with a pairing", which is three
groups $G_1, G_2, G_T$ of prime order $p$ (hence, all isomorphic cyclic groups)
together with a function $e \colon G_1 \times G_2 \to G_T$ such that for any
$a_1, a_2 \in \Z$, $g_1 \in G_1$, $g_2 \in G_2$, we have

$$
e(a_1 \cdot g_1, a_2 \cdot g_2) = a_1 a_2 \cdot e(g_1, g_2)
$$

$e$ is called a "pairing" or a "bilinear pairing". What this lets us do is
"multiply in the scalar" but only once.

Fix a degree bound $d$ on the polynomials we would like to be able to commit to.
The KZG scheme, will let us commit to polynomials in $\mathbb{F}_p[x]_{< d}$. As
a preliminary, fix generators $g_1 \in G_1, g_2 \in G_2$ arbitrarily.

The first thing to know about the KZG scheme is it requires that we randomly
sample some group elements to help us. This is the dreaded and much discussed
**trusted setup**. So, anyway, we start by sampling $\tau$ at random from
$\mathbb{F}_p$ and computing for $i < d$,

$$
h_{i} := (\tau^i) \cdot g_1 \\
w := \tau \cdot g_2
$$

And then **throw away $\tau$**. The security depends on no one knowing $\tau$,
which is sometimes referred to as the **toxic waste** of the trusted setup.
Basically we compute the generator scaled by powers of $\tau$ up to the degree
bound. We make a security assumption about the groups which says that all anyone
can really do with group elements is take linear combinations of them.

Now suppose we have a polynomial $f \in \mathbb{F}_p[x]_{<d}$ with
$f = \sum_{i < d} a_i x^i$ that we would like to commit to. We will describe a
version of the scheme that is binding but not hiding, so it may leak information
about the polynomial. Now, to commit to $f$, we compute

$$
c_f := \mathsf{commit}(f) = a_0 \cdot h_{0} + a_1 \cdot h_{1} + \dots + a_{d-1} \cdot h_{d-1}
$$

so that $c_f \in G_1$ and

$$
\begin{aligned}
c_f &= \sum_{i< d} a_i \cdot h_{i} \\
&= \sum_{i < d} a_i \cdot \tau^i g_1 \\
&= \sum_{i < d} (a_i  \tau^i) \cdot g_1 \\
&= \left( \sum_{i <d} a_i \tau^i \right) \cdot g_1 \\
&= f(\tau) \cdot g_1
\end{aligned}
$$

So $c_f$ is $g_1$ scaled by $f(\tau)$ and the fact that $G_1$ is an
$\mathbb{F}_p$-module (i.e. a vector space whose scalars come from
$\mathbb{F}_p$) means we can compute $f(\tau) \cdot g_1$ from the $h_{i}$ and
the coefficients of $f$ without knowing $\tau$.

Now how does opening work? Well, say we want to open at a point $a$ to
$b = f(a)$. Then the polynomial $f - b$ vanishes at $a$, which means that it is
divisible by the polynomial $x - a$ (exercise, use polynomial division and
analyze the remainder).

So, the opener can compute the polynomial

$$
q := \frac{f - b}{x - a}
$$

and commit to it as above to get a commitment $c_q$. And $c_q$ will be the
opening proof. It remains only to describe verification. It works like this

$$
\mathsf{verify}(c_f, (b, c_q)) := e(c_q, w - a \cdot g_2)=_? e(c_f - b \cdot g_1, g_2)
$$

This amounts to checking: _"is the polynomial committed to $c_f$ equal to the
polynomial committed to by $c_q$ times $x - a$"?_

To see why, remember that $w = \tau \cdot g_2$, and say $c_q = s_q\cdot g_1$ and
$c_f = s_f \cdot g_1$ so we are checking

$$
e(s_q \cdot g_1, (\tau - a) \cdot g_2) =_? e((s_f - b) \cdot g_1, g_2)
$$

which by the bilinearity of the pairing is the same as checking

$$
s_q \cdot (\tau - a) = s_f - b
$$

## Bootleproof inner product argument
