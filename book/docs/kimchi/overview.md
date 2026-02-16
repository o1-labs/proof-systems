# Overview

Here we explain how the Kimchi protocol design is translated into the
`proof-systems` repository, from a high level perspective, touching briefly on
all the involved aspects of cryptography. The concepts that we will be
introducing can be studied more thoroughly by accessing the specific sections in
the book.

In brief, the Kimchi protocol requires three different types of arguments
`Argument`:

- **Custom gates:** they correspond to each of the specific functions performed
  by the circuit, which are represented by gate constraints.
- **Permutation:** the equality between different cells is constrained by copy
  constraints, which are represented by a permutation argument. It represents
  the wiring between gates, the connections from/to inputs and outputs.
- **Lookup tables:** for efficiency reasons, some public information can be
  stored by both parties (prover and verifier) instead of wired in the circuit.
  Examples of these are boolean functions.

All of these arguments are translated into equations that must hold for a
correct witness for the full relation. Equivalently, this is to say that a
number of expressions need to evaluate to zero on a certain set of numbers. So
there are two problems to tackle here:

1. **Roots-check:** Check that an equation evaluates to zero on a set of
   numbers.
2. **Aggregation:** Check that it holds for each of the equations.

### Roots-check

For the first problem, given a polynomial $p(X)$ of degree $d$, we are asking to
check that $p(x)=0$ for all $x\in S$, where $S$ stands for set. Of course, one
could manually evaluate each of the elements in the set and make sure of the
above claim. But that would take so long (i.e. it wouldn't be _succinct_).
Instead, we want to check that _all at once_. And a great way to do it is by
using a **vanishing polynomial**. Such a polynomial $v_S(X)$ will be nothing
else than the smallest polynomial that vanishes on $S$. That means, it is
exactly defined as the degree $|S|$ polynomial formed by the product of the
monomials:

$$v_S(X) = \prod_{s\in S} (X-s)$$

And why is this so advantageous? Well, first we need to make a key observation.
Since the vanishing polynomial equals zero on every $x\in S$, and it is the
smallest such polynomial (recall it has the smallest possible degree so that
this property holds), if our initial polynomial $p(X)$ evaluates to zero on $S$,
then it must be the case that $p(X)$ is a **multiple of the vanishing
polynomial** $v_S(X)$. But what does this mean _in practice_? By polynomial
division, it simply means there exists a **quotient polynomial** of degree
$d-|S|$ such that:

$$q(X) := \frac{p(X)}{v_S(X)}$$

And still, where's the hype? If you can provide such a quotient polynomial, one
could easily check that if $q(a) = p(a) / v_S(a)$ for a random number
$a\in\mathbb{F}$ \ $S$ (recall you will check in a point out of the set,
otherwise you would get a $0/0$), then with very high probability that would
mean that actually $p(X) = q(X) \cdot v_S(X)$, meaning that $p(X)$ vanishes on
the whole set $S$, with **just one point**!

Let's take a deeper look into the _"magic"_ going on here. First, what do we
mean by _high probability_? Is this even good enough? And the answer to this
question is: as good as you want it to be.

**First** we analyse the math in this check. If the polynomial form of
$p(X) = q(X) \cdot v_S(X)$ actually holds, then of course for any possible
$a\in\mathbb{F}$ \ $S$ the check $p(a) =_? q(a) \cdot v_S(a)$ will hold. But is
there any unlucky instantiation of the point $a$ such that
$p(a) = q(a) \cdot v_S(a)$ but $p(X) \neq q(X) \cdot v_S(X)$? And the answer is,
yes, there are, BUT not many. But how many? How unlikely this is? You already
know the answer to this: **Schwartz-Zippel**. Recalling this lemma:

> Given two different polynomials $f(X)$ and $g(X)$ of degree $d$, they can at
> most intersect (i.e. _coincide_) in $d$ points. Or what's equivalent, let
> $h(X) := f(X) - g(X)$, the polynomial $h(X)$ can only evaluate to $0$ in at
> most $d$ points (its roots).

Thus, if we interchange $p(X) \rightarrow f(X)$ and
$q(X)\cdot v_S(X) \rightarrow g(X)$, both of degree $d$, there are at most
$\frac{d}{|\mathbb{F}- S|}$ unlucky points of $a$ that could trick you into
thinking that $p(X)$ was a multiple of the vanishing polynomial (and thus being
equal to zero on all of $S$). So, how can you make this error probability
negligible? By having a field size that is big enough (the formal definition
says that the inverse of its size should decrease faster than any polynomial
expression). Since we are working with fields of size $2^{255}$, we are safe on
this side!

**Second**, is this really faster than checking that $p(x)=0$ for all $x\in S$ ?
At the end of the day, it seems like we need to evaluate $v_S(a)$, and since
this is a degree $|S|$ polynomial it looks like we are still performing about
the same order of computations. But here comes math again. _In practice_, we
want to define this set $S$ to have a _nice structure_ that allows us to perform
some computations more efficiently than with arbitrary sets of numbers. Indeed,
this set will normally be a **multiplicative group** (normally represented as
$\mathbb{G}$ or $\mathbb{H}$), because in such groups the vanishing polynomial
$v_\mathbb{G}(X):=\prod_{\omega\in\mathbb{G}}(X-\omega)$ has an efficient
representation $v_\mathbb{G}(X)=X^{|\mathbb{G}|}-1$, which is much faster to
evaluate than the above product.

**Third**, we may want to understand what happens with the evaluation of $p(a)$
instead. Since this is a degree $d ≥ |\mathbb{G}|$, it may look like this will
as well take a lot of effort. But here's where cryptography comes into play,
since the verifier will _never_ get to evaluate the actual polynomial by
themselves. Various reasons why. One, if the verifier had access to the full
polynomial $p(X)$, then the prover should have sent it along with the proof,
which would require $d+1$ coefficients to be represented (and this is no longer
succinct for a SNARK). Two, this polynomial could carry some secret information,
and if the verifier could recompute evaluations of it, they could learn some
private data by evaluating on specific points. So instead, these evaluations
will be a "mental game" thanks to **polynomial commitments** and **proofs of
evaluation** sent by the prover (for whom a computation in the order of $d$ is
not only acceptable, but necessary). The actual proof length will depend heavily
on the type of polynomial commitments we are using. For example, in Kate-like
commitments, committing to a polynomial takes a constant number of group
elements (normally one), whereas in Bootleproof it is logarithmic. But in any
case this will be shorter than sending $O(d)$ elements.

### Aggregation

So far we have seen how to check that a polynomial equals zero on all of
$\mathbb{G}$, with just a single point. This is somehow an aggregation _per se_.
But we are left to analyse how we can prove such a thing, for many polynomials.
Altogether, if they hold, this will mean that the polynomials encode a correct
witness and the relation would be satisfied. These checks can be performed one
by one (checking that each of the quotients are indeed correct), or using an
efficient aggregation mechanism and checking only **one longer equation at
once**.

So what is the simplest way one could think of to perform this one-time check?
Perhaps one could come up with the idea of adding up all of the equations
$p_0(X),...,p_n(X)$ into a longer one $\sum_{i=0}^{n} p_i(X)$. But by doing
this, we may be cancelling out terms and we could get an incorrect statemement.

So instead, we can multiply each term in the sum by a random number. The reason
why this trick works is the independence between random numbers. That is, if two
different polynomials $f(X)$ and $g(X)$ are both equal to zero on a given $X=x$,
then with very high probability the same $x$ will be a root of the random
combination $\alpha\cdot f(x) + \beta\cdot g(x) = 0$. If applied to the whole
statement, we could transform the $n$ equations into a single equation,

$$\bigwedge_{i_n} p_i(X) =_? 0 \Leftrightarrow_{w.h.p.} \sum_{i=0}^{n} \rho_i \cdot p_i(X) =_? 0$$

This sounds great so far. But we are forgetting about an important part of proof
systems which is proof length. For the above claim to be sound, the random
values used for aggregation should be verifier-chosen, or at least
prover-independent. So if the verifier had to communicate with the prover to
inform about the random values being used, we would get an overhead of $n$ field
elements.

Instead, we take advantage of another technique that is called
**powers-of-alpha**. Here, we make the assumption that powers of a random value
$\alpha^i$ are indistinguishable from actual random values $\rho_i$. Then, we
can twist the above claim to use only one random element $\alpha$ to be agreed
with the prover as:

$$\bigwedge_{i_n} p_i(X) =_? 0 \Leftrightarrow_{w.h.p.} \sum_{i=0}^{n} \alpha^i \cdot p_i(X) =_? 0$$
