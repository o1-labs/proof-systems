# $\plookup$ in Kimchi

In 2020, [$\plookup$](https://eprint.iacr.org/2020/315.pdf) showed how to create
lookup proofs. Proofs that some witness values are part of a
[lookup table](https://en.wikipedia.org/wiki/Lookup_table). Two years later, an
independent team published [plonkup](https://eprint.iacr.org/2022/086) showing
how to integrate $\plookup$ into $\plonk$.

This document specifies how we integrate $\plookup$ in kimchi. It assumes that
the reader understands the basics behind $\plookup$.

## Overview

We integrate $\plookup$ in kimchi with the following differences:

- we snake-ify the sorted table instead of wrapping it around (see later)
- we allow fixed-ahead-of-time linear combinations of columns of the queries we
  make
- we implemented different tables, like RangeCheck and XOR.
  <!-- This sentence must be changed if we update ../../../kimchi/src/circuits/lookup/tables/mod.rs -->
- we allow several lookups (or queries) to be performed within the same row
- zero-knowledgeness is added in a specific way (see later)

The following document explains the protocol in more detail

### Recap on the grand product argument of $\plookup$

As per the $\plookup$ paper, the prover will have to compute three vectors:

- $f$, the (secret) **query vector**, containing the witness values that the
  prover wants to prove are part of the lookup table.
- $t$, the (public) **lookup table**.
- $s$, the (secret) concatenation of $f$ and $t$, sorted by $t$ (where elements
  are listed in the order they are listed in $t$).

Essentially, $\plookup$ proves that all the elements in $f$ are indeed in the
lookup table $t$ if and only if the following multisets are equal:

- $\{(1+\beta)f, \text{diff}(t)\}$
- $\text{diff}(\text{sorted}(f, t))$

where $\text{diff}$ is a new set derived by applying a "randomized difference"
between every successive pairs of a vector, and $(f, t)$ is the set union of $f$
et $t$.

More precisely, for a set $S =
\{s_{0}, s_{1}, \cdots, s_{n} \}$,
$\text{diff}(S)$ is defined as the set
$\{s_{0} + \beta s_{1}, s_{1} + \beta s_{2}, \cdots, s_{n - 1} + \beta s_{n}\}$.

For example, with:

- $f = \{5, 4, 1, 5\}$
- $t = \{1, 4, 5\}$

we have:

- $\text{sorted}(f,t) = \{1, 1, 4, 4, 5, 5, 5\}$
- $\{\color{blue}{(1+\beta)f}, \color{green}{\text{diff}(t)}\} = \{\color{blue}{(1+\beta)5, (1+\beta)4, (1+\beta)1, (1+\beta)5}, \color{green}{1+\beta 4, 4+\beta 5}\}$
- $\text{diff}(\text{sorted}(f, t)) = \{1+\beta 1, 1+\beta 4, 4+\beta 4, 4+\beta 5, 5+\beta 5, 5+\beta 5\}$

> Note: This assumes that the lookup table is a single column. You will see in
> the next section how to address lookup tables with more than one column.

The equality between the multisets can be proved with the permutation argument
of $\plonk$, which would look like enforcing constraints on the following
accumulator:

- init: $\mathsf{acc}_0 = 1$
- final: $\mathsf{acc}_n = 1$
- for every $0 < i \leq n$:
  $$
  \mathsf{acc}_i = \mathsf{acc}_{i-1} \cdot \frac{(\gamma + (1+\beta) f_{i-1}) \cdot (\gamma + t_{i-1} + \beta t_i)}{(\gamma + s_{i-1} + \beta s_{i})(\gamma + s_{n+i-1} + \beta s_{n+i})}
  $$

Note that the $\plookup$ paper uses a slightly different equation to make the
proof work. It is possible that the proof would work with the above equation,
but for simplicity let's just use the equation published in $\plookup$:

$$
\mathsf{acc}_i = \mathsf{acc}_{i-1} \cdot \frac{(1+\beta) \cdot (\gamma + f_{i-1}) \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})(\gamma(1+\beta) + s_{n+i-1} + \beta s_{n+i})}
$$

> Note: in $\plookup$ $s$ is longer than $n$ ($|s| = |f| + |t|$), and thus it
> needs to be split into multiple vectors to enforce the constraint at every
> $i \in [[0;n]]$. This leads to the two terms in the denominator as shown
> above, so that the degree of $\gamma (1 + \beta)$ is equal in the nominator
> and denominator.

### Lookup tables

<!-- This sentence must be changed if we update ../../../kimchi/src/circuits/lookup/tables/mod.rs -->

Kimchi uses different lookup tables, including RangeCheck and XOR. The XOR table
for values of 1 bit is the following:

| l   | r   | o   |
| --- | --- | --- |
| 1   | 0   | 1   |
| 0   | 1   | 1   |
| 1   | 1   | 0   |
| 0   | 0   | 0   |

Whereas kimchi uses the XOR table for values of $4$ bits, which has $2^{8}$
entries.

Note: the $(0, 0, 0)$ **entry** is at the very end on purpose (as it will be
used as dummy entry for rows of the witness that don't care about lookups).

### Querying the table

The $\plookup$ paper handles a vector of lookups $f$ which we do not have. So
the first step is to create such a table from the witness columns (or
registers). To do this, we define the following objects:

- a **query** tells us what registers, in what order, and scaled by how much,
  are part of a query
- a **query selector** tells us which rows are using the query. It is pretty
  much the same as a gate selector.

Let's go over the first item in this section.

For example, the following **query** tells us that we want to check if
$r_0 \oplus r_2 = 2\cdot r_1$

|    l     |    r     |    o     |
| :------: | :------: | :------: |
| 1, $r_0$ | 1, $r_2$ | 2, $r_1$ |

$r_0$, $r_1$ and $r_2$ will be the result of the evaluation at $g^i$ of
respectively the wire polynomials $w_0$, $w_1$ and $w_2$. To perform vector
lookups (i.e. lookups over a list of values, not a single element), we use a
standard technique which consists of coining a combiner value $j$ and sum the
individual elements of the list using powers of this coin.

The grand product argument for the lookup constraint will look like this at this
point:

$$
\mathsf{acc}_i = \mathsf{acc}_{i-1} \cdot \frac{(1+\beta) \cdot {\color{green}(\gamma + j^0 \cdot 1 \cdot w_0(g^i) + j \cdot 1 \cdot w_2(g^i) + j^2 \cdot 2 \cdot w_1(g^i))} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})(\gamma(1+\beta) + s_{n+i-1} + \beta s_{n+i})}
$$

Not all rows need to perform queries into a lookup table. We will use a query
selector in the next section to make the constraints work with this in mind.

### Query selector

The associated **query selector** tells us on which rows the query into the XOR
lookup table occurs.

| row | query selector |
| :-: | :------------: |
|  0  |       1        |
|  1  |       0        |

Both the (XOR) lookup table and the query are built-ins in kimchi. The query
selector is derived from the circuit at setup time.

With the selectors, the grand product argument for the lookup constraint has the
following form:

$$
\mathsf{acc}_i = \mathsf{acc}_{i-1} \cdot \frac{(1+\beta) \cdot {\color{green}\mathsf{query}} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})}
$$

where $\color{green}{\mathsf{query}}$ is constructed so that a dummy query
($0 \oplus 0 = 0$) is used on rows that don't have a query.

$$
\begin{aligned}
\mathsf{query} := &\ \mathsf{selector} \cdot (\gamma + j^0 \cdot 1 \cdot w_0(g^i) + j \cdot 1 \cdot w_2(g^i) + j^2 \cdot 2 \cdot w_1(g^i)) + \\
&\ (1- \mathsf{selector}) \cdot (\gamma + 0 + j \cdot 0 + j^2 \cdot 0)
\end{aligned}
$$

### Supporting multiple queries

Since we would like to allow multiple table lookups per row, we define multiple
**queries**, where each query is associated with a **lookup selector**.

Previously, ChaCha20 was implemented in Kimchi but has been removed as it has
become unneeded. You can still find the implementation
[here](https://github.com/o1-labs/proof-systems/blob/601e0adb2a4ba325c9a76468b091ded2bc7b0f70/kimchi/src/circuits/polynomials/chacha.rs).
The `ChaCha` gates all perform $4$ queries in a row. Thus, $4$ is trivially the
largest number of queries that happen in a row.

**Important**: to make constraints work, this means that each row must make $4$
queries. Potentially some or all of them are dummy queries.

For example, the `ChaCha0`, `ChaCha1`, and `ChaCha2` gates will jointly apply
the following 4 XOR queries on the current and following rows:

|    l     |    r     |      o      | -   |    l     |    r     |      o      | -   |    l     |    r     |      o      | -   |    l     |      r      |      o      |
| :------: | :------: | :---------: | --- | :------: | :------: | :---------: | --- | :------: | :------: | :---------: | --- | :------: | :---------: | :---------: |
| 1, $r_3$ | 1, $r_7$ | 1, $r_{11}$ | -   | 1, $r_4$ | 1, $r_8$ | 1, $r_{12}$ | -   | 1, $r_5$ | 1, $r_9$ | 1, $r_{13}$ | -   | 1, $r_6$ | 1, $r_{10}$ | 1, $r_{14}$ |

which you can understand as checking for the current and following row that

$$
\begin{aligned}
r_3 \oplus r_7 &= r_{11}\\
r_4 \oplus r_8 &= r_{12}\\
r_5 \oplus r_9 &= r_{13}\\
r_6 \oplus r_{10} &= r_{14}
\end{aligned}
$$

The `ChaChaFinal` also performs $4$ (somewhat similar) queries in the XOR lookup
table. In total this is $8$ different queries that could be associated to $8$
selector polynomials.

### Grouping queries by queries pattern

Associating each query with a selector polynomial is not necessarily efficient.
To summarize:

- the `ChaCha0`, `ChaCha1`, and `ChaCha2` gates that in total make $4$ queries
  into the XOR table
- the `ChaChaFinal` gate makes another $4$ different queries into the XOR table

Using the previous section's method, we'd have to use $8$ different lookup
selector polynomials for each of the different $8$ queries. Since there's only
$2$ use-cases, we can simply group them by **queries patterns** to reduce the
number of lookup selector polynomials to $2$.

The grand product argument for the lookup constraint looks like this now:

$$
\mathsf{acc}_i = \mathsf{acc}_{i-1} \cdot \frac{{\color{green}(1+\beta)^4 \cdot \mathsf{query}} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})\times \ldots}
$$

where $\color{green}{\mathsf{query}}$ is constructed as:

$$
\begin{aligned}
\mathsf{query} = &\ \mathsf{selector}_1 \cdot \mathsf{pattern}_1 + \\
&\ \mathsf{selector}_2 \cdot \mathsf{pattern}_2 + \\
&\ (1 - \mathsf{selector}_1 - \mathsf{selector}_2) \cdot (\gamma + 0 + j \cdot 0 + j^2 \cdot 0)^4
\end{aligned}
$$

where, for example the first pattern for the `ChaCha0`, `ChaCha1`, and `ChaCha2`
gates looks like this:

$$
\begin{aligned}
\mathsf{pattern}_1 = &\ (\gamma + w_3(g^i) + j \cdot w_7(g^i) + j^2 \cdot w_{11}(g^i)) \cdot \\
&\ (\gamma + w_4(g^i) + j \cdot w_8(g^i) + j^2 \cdot w_{12}(g^i)) \cdot \\
&\ (\gamma + w_5(g^i) + j \cdot w_9(g^i) + j^2 \cdot w_{13}(g^i)) \cdot \\
&\ (\gamma + w_6(g^i) + j \cdot w_{10}(g^i) + j^2 \cdot w_{14}(g^i)) \cdot \\
\end{aligned}
$$

Note that there's now $4$ dummy queries, and they only appear when none of the
lookup selectors are active. If a pattern uses less than $4$ queries, it has to
be padded with dummy queries as well.

Finally, note that the denominator of the grand product argument is incomplete
in the formula above. Since the nominator has degree $5$ in
$\gamma (1 + \beta)$, the denominator must match too. This is achieved by having
a longer $s$, and referring to it $5$ times. The denominator thus becomes
$\prod_{k=1}^{5} (\gamma (1+\beta) + s_{kn+i-1} + \beta s_{kn+i})$.

## Back to the grand product argument

There are two things that we haven't touched on:

- The vector $t$ representing the **combined lookup table** (after its columns
  have been combined with a joint combiner $j$). The **non-combined lookup
  table** is fixed at setup time and derived based on the lookup tables used in
  the circuit.
- The vector $s$ representing the sorted multiset of both the queries and the
  lookup table. This is created by the prover and sent as commitment to the
  verifier.

The first vector $t$ is quite straightforward to think about:

- if it is smaller than the domain (of size $n$), then we can repeat the last
  entry enough times to make the table of size $n$.
- if it is larger than the domain, then we can either increase the domain or
  split the vector in two (or more) vectors. This is most likely what we will
  have to do to support multiple lookup tables later.

What about the second vector $s$?

## The sorted vector $s$

We said earlier that in original $\plonk$ the size of $s$ is equal to
$|s| = |f|+|t|$, where $f$ encodes queries, and $t$ encodes the lookup table.
With our multi-query approach, the second vector $s$ is of the size

$$n \cdot |\#\text{queries}| + |\text{lookup\_table}|$$

That is, it contains the $n$ elements of each **query vectors** (the actual
values being looked up, after being combined with the joint combinator, that's
$4$ per row), as well as the elements of our lookup table (after being combined
as well).

Because the vector $s$ is larger than the domain size $n$, it is split into
several vectors of size $n$. Specifically, in the plonkup paper, the two halves
of $s$, which are then interpolated as $h_1$ and $h_2$. The denominator in
$\plonk$ in the vector form is

$$
\big(\gamma(1+\beta) + s_{i-1} + \beta s_{i}\big)\big(\gamma(1+\beta)+s_{n+i-1} + \beta s_{n+i}\big)
$$

which, when interpolated into $h_1$ and $h_2$, becomes

$$
\big(\gamma(1+\beta) + h_1(x) + \beta h_1(g \cdot x)\big)\big(\gamma(1+\beta) + h_2(x) + \beta h_2(g \cdot x)\big)
$$

Since one has to compute the difference of every contiguous pairs, the last
element of the first half is the replicated as the first element of the second
half ($s_{n-1} = s_{n}$). Hence, a separate constraint must be added to enforce
that continuity on the interpolated polynomials $h_1$ and $h_2$:

$$L_{n-1}(X)\cdot\big(h_1(X) - h_2(g \cdot X)\big) \equiv 0$$

which is equivalent to checking that $h_1(g^{n-1}) = h_2(1)$.

## The sorted vector $s$ in kimchi

Since this vector is known only by the prover, and is evaluated as part of the
protocol, zero-knowledge must be added to the corresponding polynomial (in case
of $\plookup$ approach, to $h_1(X),h_2(X)$). To do this in kimchi, we use the
same technique as with the other prover polynomials: we randomize the last
evaluations (or rows, on the domain) of the polynomial.

This means two things for the lookup grand product argument:

1. We cannot use the wrap around trick to make sure that the list is split in
   two correctly (enforced by $L_{n-1}(h_1(x) - h_2(g \cdot x)) = 0$ which is
   equivalent to $h_1(g^{n-1}) = h_2(1)$ in the $\plookup$ paper)
2. We have even less space to store an entire query vector. Which is actually
   super correct, as the witness also has some zero-knowledge rows at the end
   that should not be part of the queries anyway.

The first problem can be solved in two ways:

- **Zig-zag technique**. By reorganizing $s$ to alternate its values between the
  columns. For example, $h_1 = (s_0, s_2, s_4, \cdots)$ and
  $h_2 = (s_1, s_3, s_5, \cdots)$ so that you can simply write the denominator
  of the grand product argument as
  $$(\gamma(1+\beta) + h_1(x) + \beta h_2(x))(\gamma(1+\beta)+ h_2(x) + \beta h_1(x \cdot g))$$
  Whis approach is taken by the [plonkup](https://eprint.iacr.org/2022/086)
  paper.
- **Snake technique**. By reorganizing $s$ as a snake. This is what is currently
  implemented in kimchi.

The snake technique rearranges $s$ into the following shape:

```
                           __    _
          s_0 |  s_{2n-1} |  |  | |
          ... |       ... |  |  | |
      s_{n-1} |       s_n |  |  | |
               ‾‾‾‾‾‾‾‾‾‾‾    ‾‾   ‾
              h1         h2  h3 ...
```

Assuming that for now we have only one bend and two polynomials $h_1(X),h_2(X)$,
the denominator has the following form:

$$\big(\gamma(1+\beta) + h_1(x) + \beta h_1(x \cdot g)\big)\big(\gamma(1+\beta)+ h_2(x \cdot g) + \beta h_2(x)\big)$$

and the snake doing a U-turn is constrained via $s_{n-1} = s_n$, enforced by the
following equation:

$$L_{n-1} \cdot (h_1(x) - h_2(x)) = 0$$

In practice, $s$ will have more sections than just two. Assume that we have $k$
sections in total, then the denominator generalizes to

$$
\prod_{i=1}^k \gamma(1+\beta) + h_i(x \cdot g^{\delta_{0,\ i \text{ mod } 2}}) + \beta h_i(x \cdot g^{\delta_{1,\ i \text{ mod } 2}})
$$

where $\delta_{i,j}$ is Kronecker delta, equal to $1$ when $i$ is even (for the
first term) or odd (for the second one), and equal to $0$ otherwise.

Similarly, the U-turn constraints now become

$$
\begin{align*}
L_{n-1}(X) \cdot (h_2(X) - h_1(X)) &\equiv 0\\
\color{green}L_{0}(X) \cdot (h_3(X) - h_2(X)) &\color{green}\equiv 0\\
\color{green}L_{n-1}(X) \cdot (h_4(X) - h_3(X)) &\color{green}\equiv 0\\
\ldots
\end{align*}
$$

In our concrete case with $4$ simultaneous lookups the vector $s$ has to be
split into $k= 5$ sections --- each denominator term in the accumulator accounts
for $4$ queries ($f$) and $1$ table consistency check ($t$).

## Unsorted $t$ in $s$

Note that at setup time, $t$ cannot be sorted lexicographically as it is not
combined yet. Since $s$ must be sorted by $t$ (in other words sorting of $s$
must follow the elements of $t$), there are two solutions:

1. Both the prover and the verifier can sort the combined $t$ lexicographically,
   so that $s$ can be sorted lexicographically too using typical sorting
   algorithms
2. The prover can directly sort $s$ by $t$, so that the verifier doesn't have to
   do any pre-sorting and can just rely on the commitment of the columns of $t$
   (which the prover can evaluate in the protocol).

We take the second approach. However, this must be done carefully since the
combined $t$ entries can repeat. For some $i, l$ such that $i \neq l$, we might
have

$$
t_0[i] + j \cdot t_1[i] + j^2 \cdot t_2[i] = t_0[l] + j \cdot t_1[l] + j^2 \cdot t_2[l]
$$

For example, if $f = \{1, 2, 2, 3\}$ and $t = \{2, 1, 2, 3\}$, then
$\text{sorted}(f, t) = \{2, 2, 2, 1, 1, 2, 3, 3\}$ would be a way of correctly
sorting the combined vector $s$. At the same time
$\text{sorted}(f, t) = \{ 2, 2, 2, 2, 1, 1, 3, 3 \}$ is incorrect since it does
not have a second block of $2$s, and thus such an $s$ is not sorted by $t$.

## Recap

So to recap, to create the sorted polynomials $h_i$, the prover:

1. creates a large query vector which contains the concatenation of the $4$
   per-row (combined with the joint combinator) queries (that might contain
   dummy queries) for all rows
2. creates the (combined with the joint combinator) table vector
3. sorts all of that into a big vector $s$
4. divides that vector $s$ into as many $h_i$ vectors as a necessary following
   the snake method
5. interpolate these $h_i$ vectors into $h_i$ polynomials
6. commit to them, and evaluate them as part of the protocol.
