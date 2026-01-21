# Inductive proof systems

Earlier we defined zero-knowledge proofs as being proofs of a computation of a
function $f \colon A \times W \to \mathsf{Bool}$.

We will now go beyond this, and try to define zero-knowledge proof systems for
computations that proceed **inductively**. That is, in pieces, and potentially
over different locations involving different parties in a distributed manner.

An example of an **inductive computation** would be the verification of the Mina
blockchain. Each block producer, when they produce a new block,

- verifies that previous state of the chain was arrived at correctly

- verifies that their VRF evaluation is sufficient to extend the chain

- verifies a transaction proof, corresponding to the correctness of executing a
  bundle of Mina transactions

You can imagine the whole computation of verifying the chain, from a global view
as being chopped up into per-block steps, and then each step is executed by a
different block producer, relying on information which is private to that
block-producer (for example, the private key needed to evaluate their VRF, which
is never broadcast on the network).

But, at the end of the day, we end up with exactly one proof which summarizes
this entire computation.

That is what **inductive SNARKs** (or in my opinion less evocatively recursive
SNARKs, or proof-carrying data) allow us to do: create a single proof certifying
the correctness of a big computation that occurred in steps, possibly across
multiple parties, and possibly with party-local private information.

Ok, so what are inductive SNARKs? Well, first let's describe precisely the
aforementioned class of distributed computations.

## Inductive sets

zk-SNARKs [as defined earlier](../fundamentals/zkbook_plonk.md) allow you to
prove for efficiently computable functions
$f \colon A \times W \to \mathsf{Bool}$ statements of the form

> I know $w \colon W$ such that $f(a, w) = \mathsf{true}$

Another way of looking at this is that they let you prove membership in sets of
the form

$A_f := \{ a \colon A \mid \text{There exists } w \colon W \text{ such that} f(a, w) = \mathsf{true} \}$[^1]

These are called [NP sets](<https://en.wikipedia.org/wiki/NP_(complexity)>). In
intuitive terms, an NP set is one in which membership can be efficiently checked
given some "witness" or helper information (which is $w$).

Inductive proof systems let you prove membership in sets that are inductively
defined. An inductively defined set is one where membership can be efficiently
checked given some helper information, but the computation is explicitly
segmented into pieces.

Let's give the definition first and then I will link to a blog post that
discusses an example.

We will give a recursive definition of a few concepts. Making this
mathematically well-founded would require a little bit of work which is sort of
just bureaucratic, so we will not do it. The concepts we'll define recursively
are

- **inductive set**

- **inductive rule**

The data of an **inductive rule for a type $A$** is

- a sequence of inductive sets $A_0, \dots, A_{n-1}$ (note the recursive
  reference to )

- a type $W$

- a function
  $f \colon A \times W \times A_0 \times \dots A_{n-1} \to \mathsf{Bool}$. So
  this function is like our function for NP sets, but it also takes in the
  previous values from other inductive sets.

The data of an **inductive set over a type $A$** is

- a sequence of inductive rules for the type $A$, $R= (r_0, \dots, r_{m-1})$

The subset of $A$ corresponding to $R$ (which we will for now write $A_R$) is
defined inductively as follows.

For $a \colon A$, $a \in A_R$ if and only if

- there is some inductive rule $r$ in the sequence $R$ with function
  $f \colon A \times W_r \times A_{r,0} \times \dots A_{r, n_r-1} \to \mathsf{Bool}$
  such that

- there exists $w \colon W_{r}$ and $a_i \in A_{r, i}$ [^2] for each $i < n_r$
  such that

- $f(a, w, a_0, \dots, a_1) = \mathsf{True}$

Actually there is a distinction between an inductive set $A$, the type
underlying it, and the subset of that type which belongs to that set. But it is
messy to explicitly keep track of this distinction for the most part so we will
equivocate between the 3 concepts.

[^1]:
    Technical note which is fine to ignore, $A_f$ would be more appropriately
    defined by saying "There exists some efficiently computed $w\colon W$".

[^2]:
    Here the notion of membership in an inductive set is recursively referred
    to.

---

See [this blog post](https://zkproof.org/2020/06/08/recursive-snarks/)
