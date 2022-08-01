# Accumulation

## Introduction

The trick below was originally described in [Halo](https://eprint.iacr.org/2020/499.pdf),
however we are going to base this post on the abstraction of "accumulation schemes" described by Bünz, Chiesa, Mishra and Spooner in [Proof-Carrying Data from Accumulation Schemes](/https://eprint.iacr.org/2020/499.pdf), in particular the scheme in Appendix A. 2.

Relevant resources include:

- [Proof-Carrying Data from Accumulation Schemes](https://eprint.iacr.org/2020/499.pdf) by Benedikt Bünz, Alessandro Chiesa, Pratyush Mishra and Nicholas Spooner.
- [Recursive Proof Composition without a Trusted Setup (Halo)](https://eprint.iacr.org/2019/1021.pdf) by Sean Bowe, Jack Grigg and Daira Hopwood.

This page describes the most relevant parts of these papers and how it is implemented in Pickles/Kimchi.
It is not meant to document the low-level details of the code in Pickles, but to describe what the code aims to do,
allowing someone reviewing / working on this part of the codebase to gain context.

## Interactive Reductions Between Relations

The easiest way to understand "accumulation" is as a set of interactive reductions between relations.

An interactive reduction $\relation \to \relation'$ proceeds as follows:

- The prover/verifier starts with some statement $\statement$, the prover additionally holds $\witness$.
- They then run some protocol between them.
- After which, they both obtain $\statement'$ and the prover obtains $\witness'$

With the security/completeness guarantee that:

$$
(\statement, \witness) \in \relation
\iff
(\statement', \witness') \in \relation'
$$

Except with negligible probability.
In other words: we have reduced membership of $\relation$ to membership of $\relation'$
using interaction between the parties: the reduction may be probabilistic.
Foreshadowing here is a diagram/overview of the reductions
(the relations will be described as we go)
used in Pickles:

<figure>
<div style="text-align: center;">
<img src="./reductions.svg" alt="Commucation diagram of interactive/non-deterministic reductions between languages" width="70%">
</div>
<figcaption>
<b>
Fig 1.
</b>
An overview the particular reductions/languages (described below) we require.
</figcaption>
</figure>

As you can see from Fig. 1, we have a cycle of reductions (following the arrows) e.g. we can reduce a relation "$\relation_{\mathsf{Acc}, \vec{G}}$" to itself by applying all 4 reductions. This may seem useless: why reduce a relation to itself?

However the crucial point is the "in-degree" (e.g. n-to-1) of these reductions:
take a look at the diagram and note that
<u>any</u> number of $\relation_{\mathsf{Acc}, \vec{G}}$ instances can be reduced to a <u>single</u> $\relation_{\mathsf{PCS},d}$ instance!
This $\relation_{\mathsf{PCS},d}$ instance can then be converted to a single $\relation_{\mathsf{Acc},\vec{G}}$
by applying the reductions (moving "around the diagram"):

$$
\relation_{\mathsf{PCS},d} \to
\relation_{\mathsf{IPA},\ell}  \to
\relation_{\mathsf{IPA},1} \to
\relation_{\mathsf{Acc},\vec{G}}
$$

**Note:** There are many examples of interactive reductions, an example familiar to the reader is PlonK itself:
which reduces circuit-satisfiability $\relation_{C}$ ($\statement$ is the public inputs and $\witness$ is the wire assignments)
to openings of polynomial commitments $\relation_{\mathsf{PCS}, d}$ ($\statement'$ are polynomial commitments and evaluation points, $\witness$ is the opening of the commitment).

<details>
<summary>
More Theory/Reflections about Interactive Reductions (click to expand)
</summary>
<br>

As noted in
[Compressed $\Sigma$-Protocol Theory and Practical Application to Plug & Play Secure Algorithmics](https://eprint.iacr.org/2020/152.pdf)
every Proof-of-Knowledge (PoK) with $k$-rounds for a relation $\relation$ can instead be seen as a reduction to some relation $\relation'$
with $k-1$ rounds as follows:

- Letting $\statement'$ be the view of the verifier.
- $\witness'$ be a $k$'th-round message which could make the verifier accept.

Hence the relation $\relation'$ is the set of verifier views (except for the last round) and the last missing message which would make the verifier accept if sent.

This simple, yet beautiful, observation turns out to be <u>extremely useful</u>: rather than explicitly sending the last-round message (which may be large/take the verifier a long time to check), the prover can instead prove that <u>he knows</u> a last-round message which <u>would make the verifier accept</u>, after all, sending the witness $\witness'$ is a particularly simple/inefficient PoK for $(\statement', \witness') \in \relation'$.

The reductions in this document are all of this form (including the folding argument):
receiving/verifying the last-round message would require too many resources (time/communication) of the verifier,
hence we instead replace it with yet another reduction to yet another language (e.g. where the witness is now half the size).

Hence we end up with a chain of reductions: going from the languages of the last-round messages.
An "accumulation scheme" is just an example of such a chain of reductions which happens to be a cycle.
Meaning the language is "self-reducing" via a series of interactive reductions.

</details>

**A Note On Fiat-Shamir:** All the protocols described here are public coin and hence in implementation
the Fiat-Shamir transform is applied to avoid interaction: the verifiers challenges are sampled using a hash function (e.g. Poseidon) modelled as a reprogrammable random oracle.

<!--

## Accumulation schemes at a high level

At a high-level accumulation schemes is about _interactively/non-deterministically_ reducing membership of two (or more) instances $\mathsf{qx} \in \language_\mathsf{q}$ (instance language), $\mathsf{acc}.x \in \language_\mathsf{acc}$ (accumulation language) to membership of $\mathsf{acc}^*.x \in \language_\mathsf{acc}$ such that if:

$$\mathsf{qx} \notin \language_\mathsf{q} \lor \mathsf{acc}.x \notin \language_\mathsf{acc}$$

Then $\mathsf{acc}^*.x \notin \language_\mathsf{acc}$ with overwhelming probability (over the random coins of the verifier).

In other words: a prover holding
$(\mathsf{qx}, \mathsf{qw}) \in \relation_\mathsf{q}$,
$(\mathsf{acc}.x, \mathsf{acc}.w) \in \relation_\mathsf{acc}$
and a verifier holding
$\mathsf{qx}$,
$\mathsf{acc}.x$
engages in an (public-coin) protocol, which outputs $(\mathsf{acc}^*.x, \mathsf{acc}^*.w) \in \relation_\mathsf{acc}$
to the prover and $\mathsf{acc}^*.x$ to the verifier, pictorially:

```mermaid
sequenceDiagram
    participant Prover
    participant Verifier

    Note left of Prover: Holds (acc.x, acc.w), (qx, qw)
    Note right of Verifier: Holds acc.x, qx

    Prover->>Verifier: m0

    Verifier->>Prover: c0

    Prover->>Verifier: m1

    Verifier->>Prover: c1

    Prover->>Verifier: ...

    Verifier->>Prover: ...

    Note left of Prover: Obtains (acc*.x, acc*.w)
    Note right of Verifier: Obtains acc*.x
```

As a design goal we want this "interactive reduction" (the "accumulation verifier") to be highly efficient, in terms of:

1. Rounds (corresponding to random oracle invocations in the compiled protocol
2. Communication.
3. Computation for the verifier.

**Note:** technically, the languages we are interested in are trivial e.g. every commitment can be opened to every polynomial,
however, we mean that no efficient adversary can find a witness for membership e.g. a valid opening.
-->

## Language of Polynomial Commitment Openings

Recall that the polynomial commitment scheme (PCS) in Kimchi is just the trivial scheme based on Pedersen commitments.
For Kimchi we are interested in "accumulation for the language ($\relation_{\mathsf{PCS}, d}$) of polynomial commitment openings", meaning that:

$$
\left(
\statement = (C, z, v),
\witness= (\vec{f})
\right)
\in
\relation_{\mathsf{PCS},d}
\iff
\left\{
\begin{align}
C &= \langle \vec{f}, \vec{G} \rangle \\
v &= \sum_{i = 0} f_i \cdot z^i
\end{align}
\right\}
$$

Where $\vec{f}$ is a list of coefficients for a polynomial $f(X) \coloneqq \sum_{i} f_i \cdot X^i$.

This is the language we are interested in reducing: providing a trivial proof, i.e. sending $\vec{f}$ requires linear communication and time of the verifier,
we want a poly-log verifier.
The communication complexity will be solved by a well-known folding argument, however to reduce computation we are going to need the "Halo trick".

First a reduction from PCS to an inner product relation.

## Reduction: $\relation_{\mathsf{PCS},d} \to \relation_{\mathsf{IPA},\ell}$

Formally the relation of the inner product argument is:

$$
(
\statement = (C, \vec{G}, H, \vec{z}),
\witness = (\vec{f})
)
\in
\relation_{\mathsf{IPA},\ell}
\iff
\left\{
v =
\langle
\vec{f},
\vec{z}
\rangle \in \FF
\land
C = \langle \vec{f}, \vec{G} \rangle + [\langle \vec{f}, \vec{z} \rangle] \cdot H \in \GG
\right\}
$$

We can reduce $(\statement = (C, z, v),
\witness = (\vec{f})) \in
\relation_{\mathsf{PCS}, d}$ to $\relation_{\mathsf{IPA}, \ell}$ with $d = \ell$ as follows:

- Define $\vec{z} = (1, z, z^2, z^3, \ldots, z^{\ell-1})$, so that $v = f(z) = \langle \vec{f}, \vec{z} \rangle$,
- The verifier adds the evaluation $v$ to the commitment "in a new coordinate" as follows:
    1. Verifier picks $H \sample \GG$ and sends $H$ to the prover.
    2. Verifier updates $C \gets C + [v] \cdot H$

Intuitively we sample a fresh $H$ to avoid a malicious prover "putting something in the $H$-position", because he must send $v$ before seeing $H$, hence he would need to guess $H$ before-hand.

If the prover is honest, we should have a commitment of the form:

$$
C =
\langle \vec{f}, \vec{G} \rangle + [v] \cdot H
=
\langle \vec{f}, \vec{G} \rangle + [\langle \vec{z}, \vec{f} \rangle] \cdot H
\in \GG
$$

**Note:** In some variants of this reduction $H$ is chosen as $[\delta] \cdot J$ for a constant $J \in \GG$ where $\delta \sample \FF$ by the verifier,
this also works, however we (in Kimchi) simply hash to the curve to sample $H$.


## Reduction: $\relation_{\mathsf{IPA},\ell} \to \relation_{\mathsf{IPA},\ell/2}$

**Note:** The folding argument described below is the particular variant implemented in Kimchi, although some of the variable names are different.

The folding argument reduces a inner product with $\ell$ (a power of two) coefficients to an inner product relation with $\ell / 2$ coefficients.
To see how it works let us rewrite the inner product in terms of a first and second part:

$$
\langle \vec{f}, \vec{z} \rangle =
\langle \vec{f}_L, \vec{z}_L \rangle
+
\langle \vec{f}_R, \vec{z}_R \rangle
\in \FF
$$

Where $\vec{f}_L = (f_1, \ldots, f_{\ell/2})$ and $\vec{f}_R = (f_{\ell/2 + 1}, \ldots, f_\ell)$,
similarly for $\vec{z}$.

Now consider a "randomized version" with a challenge $\alpha \in \FF$ of this inner product:

$$
    \begin{align}
    \langle \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R, \ \vec{z}_L + \alpha \cdot \vec{z}_R \rangle
    &=
    \alpha^{-1} \cdot  \langle \vec{f}_R, \vec{z}_L \rangle \\
    &+ \underline{\color{magenta} \left(\langle \vec{f}_R, \vec{z}_R \rangle + \langle \vec{f}_L, \vec{z}_L \rangle\right)} \\
    &+ \alpha \cdot \langle \vec{f}_L, \vec{z}_R \rangle
    \end{align}
$$

<details>
<summary>
Additional intuition: How do you arrive at the expression above? (click to expand)
</summary>
<br>
The trick is to ensure that
$\langle \vec{f}_R, \vec{z}_R \rangle + \langle \vec{f}_L, \vec{z}_L \rangle = \langle \vec{f}, \vec{z} \rangle = v$
ends up in the same power of $\alpha$.

The particular expression above is not special and arguably not the most elegant:
simpler alternatives can easily be found
and the inversion can be avoided, e.g. by instead using:
$$
    \begin{align}
    \langle \vec{f}_L + \alpha \cdot \vec{f}_R, \ \alpha \cdot \vec{z}_L + \vec{z}_R \rangle
    &= \langle \vec{f}_L, \vec{z}_R \rangle \\
    &+ \alpha  \cdot \underline{\left(\langle \vec{f}_R, \vec{z}_R \rangle + \langle \vec{f}_L, \vec{z}_L \rangle\right)} \\
    &+ \alpha^2 \cdot  \langle \vec{f}_R, \vec{z}_L \rangle
    \end{align}
$$
Which will have the same overall effect of isolating the interesting term (this time as the $\alpha$-coefficient).
The particular variant above can be found in e.g. [Compressed $\Sigma$-Protocol Theory and Practical Application to Plug & Play Secure Algorithmics](https://eprint.iacr.org/2020/152.pdf)
and proving extraction is somewhat easier than the variant used in Kimchi.
</details>

The term we care about (underlined in magenta) is $\langle \vec{f}_R, \vec{z}_R \rangle + \langle \vec{f}_L, \vec{z}_L \rangle = v$, the other two terms are cross-term garbage.
The solution is to let the prover provide commitments to the cross terms to "correct" this randomized splitting of the inner product <u>before</u> seeing $\alpha$:
the prover commits to the three terms (one of which is already provided) and the verifier computes a commitment to the new randomized inner product. i.e.

The prover sends commitment to $\langle \vec{f}_R, \vec{z}_L \rangle$ and $\langle \vec{f}_L, \vec{z}_R \rangle$ cross terms:

$$
L = \langle \vec{f}_R \Vert \vec{0}, \vec{G} \rangle + [\langle \vec{f}_R, \vec{z}_L \rangle] \cdot H
$$

<!--
$$
L = \langle \vec{f}_R, \vec{G}_L \rangle + [\langle \vec{f}_R, \vec{z}_L \rangle] \cdot H
$$
-->

$$
R = \langle \vec{0} \Vert \vec{f}_L, \vec{G} \rangle + [\langle \vec{f}_L, \vec{z}_R \rangle] \cdot H
$$

The verifier samples $\alpha \sample \FF$ and defines:

$$
\begin{align}
C' &= [\alpha^{-1}] \cdot L + C + [\alpha] \cdot R \\
   &\ \\
   &= {\langle \alpha^{-1} \cdot (\vec{f}_R \Vert \vec{0}) + (\vec{f}_L \Vert \vec{f}_R) + \alpha \cdot (\vec{0} \Vert \vec{f}_L), \vec{G} \rangle} \\
   &+
    \left[
        {
          \alpha^{-1} \cdot \langle \vec{f}_R, \vec{f}_L \rangle
          +
          {
          \color{magenta}
            \langle \vec{f}_L, \vec{z}_L \rangle
            + \langle \vec{f}_R, \vec{z}_R \rangle
            }
        + \alpha \cdot \langle \vec{f}_L, \vec{z}_R \rangle
    }\right] \cdot H \\
   &\ \\
   &=
   {\color{blue} \left\langle
        \left(
        \vec{f}_L + \alpha^{-1} \vec{f}_R
        \right)
        \Vert
        \left(
        \alpha \cdot \vec{f}_L + \vec{f}_R
        \right)
        ,
        \vec{G} \right\rangle} \\
   &+
   \left[
    {
    \color{green}
    \langle
    \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R
    ,
    \vec{z}_L
    \rangle
    +
    \langle
    \alpha \cdot \vec{f}_L +\vec{f}_R
    ,
    \vec{z}_R
    \rangle
    }
    \right] \cdot H
\end{align}
$$

The final observation in the folding argument is simply that:

$$
\alpha \vec{f}_L + \vec{f}_R
=
\alpha
\cdot
\left(
{
    \color{purple}
    \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R
}
\right)
=
\alpha
\cdot
{
\color{purple}
\vec{f}'
}
$$

Hence we can replace occurrences of $\alpha \vec{f}_L + \vec{f}_R$ by $\alpha \vec{f}'$,
with this look at the green term:

<!--
Now the final puzzle-piece of the folding argument is to notice that:
$$(\alpha \cdot \vec{f}_L + \vec{f}_R) = \alpha \cdot (\vec{f}_L + \alpha^{-1} \cdot \vec{f}_R)$$.
$$(\vec{f}_L + \alpha \cdot \vec{f}_R) = \alpha \cdot (\alpha^{-1} \cdot \vec{f}_L + \vec{f}_R)$$.
This enables us to rewrite:
-->

$$
\begin{align}
    {
    \color{green}
    \langle
    \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R
    ,
    \vec{z}_L
    \rangle
    +
    \langle
    \alpha \cdot \vec{f}_L +\vec{f}_R
    ,
    \vec{z}_R
    \rangle
    }
  &=
    {
    \langle
    \vec{f}'
    ,
    \vec{z}_L
    \rangle
    +
    \langle
    \alpha \cdot \vec{f}'
    ,
    \vec{z}_R
    \rangle
    } \\
   &=
    {
    \langle
    {
    \vec{f}'
    }
    ,
    \vec{z}_L
    \rangle
    +
    \langle
    {
    \vec{f}'
    }
    ,
    \alpha
    \cdot
    \vec{z}_R
    \rangle
    } \\
   &=
    {
    \langle
    \vec{f}'
    ,
    \vec{z}_L
    +
    \alpha
    \cdot
    \vec{z}_R
    \rangle
    } \\
    &=
    \langle
    \vec{f}',
    \vec{z}'
    \rangle
\end{align}
$$

By defining $\vec{z}' = \vec{z}_L + \alpha \cdot \vec{z}_R$.
We also rewrite the blue term in terms of $\vec{f}'$ similarly:
$$
\begin{align}
   {\color{blue} \left\langle
        \left(
        \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R
        \right)
        \Vert
        \left(
        \alpha \cdot \vec{f}_L + \vec{f}_R
        \right)
        ,
        \vec{G} \right\rangle}
    &=
   {\langle
        \vec{f}'
        \Vert
        (
        \alpha \cdot \vec{f}'
        )
        ,
        \vec{G} \rangle} \\
    &=
   {\langle
        \vec{f}'
        \Vert
        \vec{f}'
        ,
        \vec{G}_L \Vert ([\alpha] \cdot \vec{G}_R) \rangle} \\
    &=
   \langle
    \vec{f}'
    ,
    \vec{G}'
   \rangle
\end{align}
$$

By defining $\vec{G}' = \vec{G}_L + [\alpha] \cdot \vec{G}_R$.
In summary by computing:
$$
\begin{align}
C' &\gets [\alpha^{-1}] \cdot L + C + [\alpha] \cdot R \in \GG \\
\vec{f}' &\gets \vec{f}_L + \alpha^{-1} \cdot \vec{f}_R \in \FF^{\ell / 2} \\
\vec{z}' &\gets \vec{z}_L + \alpha \cdot \vec{z}_R \in \FF^{\ell / 2} \\
\vec{G}' &\gets \vec{G}_L + [\alpha] \cdot \vec{G}_R \in \GG^{\ell / 2} \\
v'       &\gets \langle \vec{f'}, \vec{z}' \rangle
\end{align}
$$

We obtain a new instance of the inner product relation (of half the size):

$$
(
\statement = (C', \vec{G}', H, \vec{z}'),
\witness = (\vec{f}', v')
) \in
\relation_{\mathsf{IPA}, \ell/2}
$$

<!--
Since (as we just verified):
$$
\begin{align}
C' &= \langle \vec{f}', \vec{G}' \rangle + [v] \cdot H \\
v &= \langle \vec{f}', \vec{z}' \rangle
\end{align}
$$
-->

At this point the prover could send $\vec{z}'$, $\vec{f}'$ to the verifier who could verify the claim:

1. Computing $\vec{G}'$ from $\alpha$ and $\vec{G}$
2. Computing $C'$ from $\vec{f}'$, $v$ and $H$
3. Checking $v \overset?= \langle \vec{f}', \vec{z}' \rangle$

This would require half as much communication as the naive proof. A modest improvement.

However, we can iteratively apply this transformation until we each an instance of constant size:

## Reduction: $\relation_{\mathsf{IPA},\ell} \to \relation_{\mathsf{IPA},1}$

That the process above can simply be applied again to the new $(C', \vec{G}', H, \vec{z}', v) \in \relation_{\mathsf{IPA}, \ell/2}$ instance as well.
By doing so $k = \log_2(\ell)$ times the total communication is brought down to $2 k$ $\GG$-elements
until the instance consists of $(\vec{C}, G, H, \vec{z}, v) \in \relation_{\mathsf{IPA}, 1}$
at which point the prover simply provides $\vec{f}' \in \FF$.

Because we need to refer to the terms in the intermediate reductions
we let
$\vec{G}^{(i)}$, $\vec{f}^{(i)}$, $\vec{z}^{(i)}$
be the
$\vec{G}'$, $\vec{f}'$, $\vec{z}'$ vectors respectively after $i$ recursive applications, with $\vec{G}^{(0)}$, $\vec{f}^{(0)}$, $\vec{z}^{(0)}$ being the original instance.
We denote by $\alpha_i$ the challenge of the $i$'th application.

## Reduction: $\relation_{\mathsf{IPA},1} \to \relation_{\mathsf{Acc},\overset{\rightarrow}{G} }$

While the proof for $\relation_{\mathsf{IPA},\ell}$ above has $O(\log(\ell))$-size, the verifiers time-complexity is $O(\ell)$:

- Computing $\vec{G}^{(k)}$ from $\vec{G}^{(0)}$ using $\vec{\alpha}$ takes $O(\ell)$.
- Computing $\vec{z}^{(k)}$ from $\vec{v}^{(0)}$ using $\vec{\alpha}$ takes $O(\ell)$.

The rest of the verifiers computation is only $O(\log(\ell))$, namely computing:

- Sampling $\alpha \sample \FF$.
- Computing $C^{(i)} \gets [\alpha_i^{-1}] \cdot L^{(i)} + C^{(i-1)} + [\alpha_i] \cdot R^{(i)}$ for every $i$

However, upon inspection, the naive claim that computing $\vec{z}^{(k)}$ takes $O(\ell)$ turns out not to be true:

**Claim:**
Define
$
h(X) \coloneqq \prod_{i = 0}^{k - 1} \left(1 + \alpha_{k - i} \cdot X^{2^i}\right)
$,
then
$
\vec{z}^{(k)} = h(z)
$ for all $z$.

**Proof:**
This can be verified by looking at the expansion of $h(X)$.
In slightly more detail:
an equivalent claim is that $z^{(k)} = \sum_{i=1}^{\ell} h_i \cdot z^{i-1}$
where $h(X) = \sum_{i=1}^\ell h_i \cdot X^{i-1}$.
Let $\vec{b}$ be the bit-decomposition of the index $i$ and observe that:
$$
h_i = \sum_{b_j} b_j \cdot \alpha_{k-i}, \text{ where } i = \sum_{j} b_j \cdot 2^j
$$
Which is simply a special case of the binomial theorem for the product:
$$(1 + \alpha_1) \cdot (1 + \alpha_2) \cdots (1 + \alpha_k)$$

Since $h(X)$ can be evaluated in $O(k)$ time, computing $\vec{z}^{(k)}$ therefore takes just $O(\log \ell)$ time!

#### The "Halo Trick"

The "Halo trick" resides in observing that this is also the case for $\vec{G}^{(k)}$:
since it is folded the same way as $\vec{z}$. It is not hard to convince one-self (using the same type of argument as above) that:

$$
\vec{G}^{(k)} = \langle \vec{h}, \vec{G} \rangle
$$

Where $\vec{h}$ is the coefficients of $h(X)$ (like $\vec{f}$ is the coefficients of $f(X)$), i.e. $h(X) = \sum_{i = 1}^{\ell} h_i X^{i-1}$

For notational convince (and to emphasise that they are 1 dimensional vectors), define/replace:

$$
U = \vec{G}^{(k)} \in \GG, \ \ \ c = \vec{f}^{(k)} \in \FF, \ \ \ h(z) = \vec{z}^{(k)} \in \FF
$$

With this we define the "accumulator language" which states that "$U$" was computed correctly:

$$
\left(\statement = (U, \vec{\alpha}), \witness = \epsilon\right)
\in
\relation_{\mathsf{Acc}, \vec{G}}
\iff
\left\{
    \begin{align}
       h(X) &\coloneqq \prod_{i = 0}^{k - 1} \left(1 + \alpha_{k - i} \cdot X^{2^i}\right)
    \land \ U = \langle \vec{h}, \vec{G} \rangle
    \end{align}
\right\}
$$

**Note:** since there is <u>no witness</u> for this relation anyone can verify the relation (in $O(\ell)$ time)
by simply computing $\langle \vec{h}, \vec{G} \rangle$ in linear time.
Instances are also small: the size is dominated by $\vec{\alpha}$ which is $|\vec{\alpha}| = \log_2 \ell$.

**In The Code:** in the Kimchi code $\vec{\alpha}$ is called `prev_challenges` and $U$ is called `comm`,
the instance $\statement$ is defined by the `RecursionChallenge` struct.

Now, using the new notation rewrite $\relation_{\mathsf{IPA},1}$ as:

$$
\left(
\statement = (C, U, H, h(z)),
\witness = (c)
\right)
\in
\relation_{\mathsf{IPA},1}
\iff
\left\{
\begin{align}
v &=
c
\cdot
h(z) \\
\land \ C &= [c] \cdot U + [v] \cdot H \in \GG
\end{align}
\right\}
$$

**Note:**
It is the same relation, we just replaced some names and simplified a bit: inner products between 1-dimensional vectors are just multiplications. The reader should convince themselves of this.

We now have all the components to reduce $\relation_{\mathsf{IPA},1} \to \relation_{\mathsf{Acc},\vec{G} }$ (with no soundness error) as follows:

1. Prover sends $c, U$ to the verifier.
2. Verifier does:
    - Compute $v \gets h(z) \cdot c$
    - Checks $C \overset?= [c] \cdot U + [ v ] \cdot H$
3. Output
$
(\statement = (U, \vec{\alpha}), \witness = \epsilon)
\in \relation_{\mathsf{Acc}, \vec{G}}
$

**Note:** The above can be optimized slight: the values of $U$ can be inferred from $H$, $v$ and $c$,
hence the prover does not need to send $U$ explicitly.
This optimization is not used in Kimchi/Pickles.

## Reduction: $\relation_{\mathsf{Acc}, \overset{\rightarrow}{G}} \to \relation_{\mathsf{PCS}, d}$

Tying the final knot in the diagram.

The expensive part in checking $
(U, \vec{\alpha})
\in
\relation_{\mathsf{Acc}, \vec{G}}
$ consists in computing
$\langle \vec{h}, \vec{G} \rangle$
given the $\vec{\alpha}$ describing $h(X)$: first expanding $\vec{\alpha}$ into $\vec{h}$, then computing the MSM.
However, by observing that
$U = \langle \vec{h}, \vec{G} \rangle$ is actually <u>a polynomial commitment</u> to $h(X)$, which we can evaluate at any point using $O(\log \ell)$ operations,
we arrive at a simple strategy for reducing any number of such claims to a single polynomial commitment opening:

1. Prover sends $U^{(1)}, \ldots, U^{(n)}$ to the verifier.
2. Verifier samples $\zeta \sample \FF$, $u \sample \FF$ and computes:

$$
\begin{align}
y &= \sum_i \ \alpha^{i-1} \cdot h^{(i)}(u) \in \FF \\
C &= \sum_i \ [\alpha^{i-1}] \cdot U^{(i)} \in \GG
\end{align}
$$

And outputs the following claim:

$$
(C, u, y) \in \language_{\mathsf{PCS},\ell}
$$

i.e. the polynomial commitment $C$ opens to $y$ at $u$. The prover has the witness:

$$
f(X) = \sum_i \ \alpha^{i-1} \cdot h^{(i)}(X)
$$

Why is this a sound reduction: if one of the $U^{(i)}$ does not commit to $h^{(i)}$ then they disagree except on at most $\ell$ points,
hence $f^{(i)}(u) \neq h^{(i)}(u)$ with probability $\ell/|\FF|$.
Taking a union bound over all $n$ terms leads to soundness error $\frac{n \ell}{|\FF|}$.

The reduction above requires $n$ $\GG$ operations and $O(n \log \ell)$ $\FF$ operations.

**In The Code:** additional polynomial commitments (i.e. from PlonK) can be added to the randomized sums $(C, u)$ above and opened at $\zeta$ as well,
this is done in Kimchi/Pickles: the $\zeta$ and $u$ above is the same as in the Kimchi code.
The combined $y$ (including both the $h(\cdot)$ evaluations and PlonK openings) is called `combined_inner_product` in Kimchi.

<figure>
<img src="./reductions-plonk.svg" alt="Commucation diagram of interactive/non-deterministic reductions between languages">
<figcaption>
<b>
Fig 2.
</b>
Cycle of reductions with the added polynomial relations being checked from PlonK.
</figcaption>
</figure>

This $\relation_{\mathsf{PCS},\ell}$ instance reduced back into a single $\relation_{\mathsf{Acc},\vec{G}}$ instance,
which is included with the proof.

**Multiple Accumulators (the case of PCD):** From the section above it may seem like there is always going to be a single $\relation_{\mathsf{Acc},\vec{G}}$ instance, this is indeed the case if the proof only verifies a single proof called Incremental Verifiable Computation (IVC) in the academic literature, however, if the proof itself verifies <u>multiple</u> proofs, called Proof-Carrying Data (PCD), then there will be multiple accumulators:
Every "input proof" includes an accumulator ($\relation_{\mathsf{Acc},\vec{G}}$ instance),
all these are combined into the new (single) $\relation_{\mathsf{Acc},\vec{G}}$ instance included in the new proof.

## Accumulation Verifier

The section above implicitly describes the work the verifier must do,
but for the sake of completeness let us explicitly describe what the verifier must do to verify a Fiat-Shamir compiled proof of the transformations above.
This constitutes "the accumulation" verifier which must be implemented "in-circuit" (in addition to the "Kimchi verifier"):

## No Cycles of Curves?

Note that the "cycles of curves" (e.g. Pasta cycle) does not show up in this part of the code:
a <u>separate accumulator</u> is needed for each curve and the final verifier must check both accumulators to deem the combined recursive proof valid.
This takes the form of `passthough` data in pickles.
