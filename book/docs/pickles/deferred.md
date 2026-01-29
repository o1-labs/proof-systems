# Deferred Computation

Let $\mathbb{F}_p$ and $\mathbb{F}_q$ be the two fields, with
$|\mathbb{E}_p(\mathbb{F}_q)| = p$, $|\mathbb{E}_q(\mathbb{F}_p)| = q$ for
Elliptic curves $\mathbb{E}_p(\mathbb{F}_q)$ and $\mathbb{E}_q(\mathbb{F}_p)$.
Assume $q > p$. We have a proof system (Kimchi) over $\mathbb{F}_p$ and
$\mathbb{F}_q$, where commitments to public inputs are:

$$
P_p = \langle \vec{e}, \vec{H} \rangle \in \mathbb{E}_p(\mathbb{F}_q) \\
P_q = \langle \vec{e}, \vec{G} \rangle \in \mathbb{E}_q(\mathbb{F}_p)
$$

Respectively. See [Pasta Curves](../specs/pasta) for more details.

When referring to the $\mathbb{F}_q$-side we mean the proof system for circuit
over the field $\mathbb{F}_q$.

## Public Inputs / Why Passing

In pickles-rs we have the notion of "passing" a variable (including the
transcript) from one side to the other. e.g. when a field element
$\alpha \in \mathbb{F}_p$ needs to be used as a scalar on $\mathbb{F}_q$.

This document explains what goes on "under the hood". Let us start by
understanding why:

Let $v \in \mathbb{F}_q$ be a scalar which we want to use to do both:

1. Field arithmetic in $\mathbb{F}_q$
2. Scalar operations on $\mathbb{E}_q(\mathbb{F}_p)$

In order to do so efficiently, we need to split these operations across two
circuits (and therefore proofs) because:

1. Emulating $\mathbb{F}_q$ arithmetic in $\mathbb{F}_p$ is very expensive, e.g.
   computing $v \cdot w$ requires $O(\log(q)^2)$ multiplications over
   $\mathbb{F}_p$: 100's of gates for a single multiplication.
2. Since $\mathbb{E}_q(\mathbb{F}_p) \subseteq \mathbb{F}_p \times \mathbb{F}_p$
   we cannot compute $[v] \cdot H \in \mathbb{E}_q(\mathbb{F}_p)$ over
   $\mathbb{F}_q$ efficiently, because, like before, emulating $\mathbb{F}_p$
   arithmetic in $\mathbb{F}_q$ is very expensive...

### Solution

The solution is to "pass" a value $v$ between the two proofs, in other words to
have two values $\tilde{v} \in \mathbb{F}_p$ and $v \in \mathbb{F}_q$ which are
equal as integers i.e. $\text{lift}(v) = \text{lift}(\tilde{v}) \in \mathbb{Z}$:
they represent "the same number". A naive first attempt would be to simply add
$\tilde{v} \in \mathbb{F}_p$ to the witness on the $\mathbb{F}_p$-side, however
this has two problems:

**Insufficient Field Size:** $p < q$ hence $v$ cannot fit in $\mathbb{F}_p$.

**No Binding:** More concerning, there is _no binding_ between the $\tilde{v}$
in the $\mathbb{F}_p$-witness and the $v$ in the $\mathbb{F}_q$-witness: a
malicious prover could choose completely unrelated values. This violates
soundness of the overall $\mathbb{F}_q/\mathbb{F}_q$-relation being proved.

#### Problem 1: Decompose

The solution to the first problem is simple:

In the $\mathbb{F}_q$-side decompose $v = 2 \cdot h + l$ with
$h \in [0, 2^{\lfloor \log p \rfloor})$ (high bits) and $l \in \{ 0, 1 \}$ (low
bit). Note $l, h < p$ since $2 p > q$; always the case for any cycle of curves,
$p$ is only $\approx \sqrt{q}$ smaller than $q$, by Hasse. Now "$\tilde{v}$" is
"represented" by the two values $\tilde{h}, \tilde{l} \in \mathbb{F}_p$.

Note that no decomposition is necessary if the "original value" $v$ was in
$\mathbb{F}_p$, since $\mathbb{F}_q$ is big enough to hold the lift of any
element in $\mathbb{F}_p$.

#### Problem 2: Compute Commitment to the Public Input of other side

To solve the binding issue we will add $l, h$ to the public inputs on the
$\mathbb{F}_p$-side, for simplicity we will describe the case where $l, h$ are
the only public inputs in the $\mathbb{F}_p$-side, which means that the
commitment $P_p \in \mathbb{E}_p(\mathbb{F}_q)$ to the public inputs on the
$\mathbb{F}_p$ side is:

$$
P_p = [h] \cdot G_h + [l] \cdot G_l \in \mathbb{E}_p(\mathbb{F}_q)
$$

At this point it is _important to note_ that $\mathbb{E}_p$ is defined over
$\mathbb{F}_q$!

Which means that we can compute $P_p \in \mathbb{E}_p(\mathbb{F}_q)$
**efficiently** on the $\mathbb{F}_q$-side!

Therefore to enforce the binding, we:

1. Add a sub-circuit which checks:
   $$
   P_p = [h] \cdot G_h + [l] \cdot G_l \in \mathbb{E}_p(\mathbb{F}_q), \\
   |h| = \lfloor \log p \rfloor \\
   |l| = 1
   $$
2. Add $P_p = (x, y) \in \mathbb{F}_q \times \mathbb{F}_q$ to the public input
   on the $\mathbb{F}_q$-side.

### We recurse onwards...

At this point the statement of the proof in $\mathbb{F}_q$-side is: the
$\mathbb{F}_q$-proof is sound, **condition** on providing an opening of $P_p$
that satisfies the $\mathbb{F}_p$-relation.

At this point you can stop and verify the proof (in the case of a "step proof"
you would), by recomputing $P_p$ outside the circuit while checking the
$\mathbb{F}_p$-relation manually "in the clear".

However, when recursing (e.g. wrapping in a "wrap proof") we need to "ingest"
this public input $P_p$; after all, to avoid blowup in the proof size everything
(proofs/accumulators/public inputs etc.) must eventually become part of the
witness and every computation covered by a circuit...

To this end, the wrap proof is a proof for the $\mathbb{F}_p$-relation with the
public input $P_p$ which additionally verifies the $\mathbb{F}_q$-proof.

The next "step" proof then verifies this wrap proof which means that $P_p$ then
becomes part of the witness!

### In Pickles

We can arbitrarily choose which side should compute the public input of the
other, in pickles we let "wrap" compute the commitment to the public input.

## Enforcing Equality

Enforces that the public input of the proof verified on the Fr side is equal to
the Fp input computed on Fr side.
