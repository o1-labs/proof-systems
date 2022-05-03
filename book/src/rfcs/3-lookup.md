# RFC: Plookup in kimchi

In 2020, [plookup](https://eprint.iacr.org/2020/315.pdf) showed how to create lookup proofs. Proofs that some witness values are part of a [lookup table](https://en.wikipedia.org/wiki/Lookup_table). Two years later, an independent team published [plonkup](https://eprint.iacr.org/2022/086) showing how to integrate Plookup into Plonk.

This document specifies how we integrate plookup in kimchi. It assumes that the reader understands the basics behind plookup.

## Overview

We integrate plookup in kimchi with the following differences:

* we snake-ify the sorted table instead of wrapping it around (see later)
* we allow fixed-ahead-of-time linear combinations of columns of the queries we make
* we only use a single table (XOR) at the moment of this writing
* we allow several lookups (or queries) to be performed within the same row
* zero-knowledgeness is added in a specific way (see later)

The following document explains the protocol in more detail

### Recap on the grand product argument of plookup

As per the Plookup paper, the prover will have to compute three vectors:

* $f$, the (secret) **query vector**, containing the witness values that the prover wants to prove are part of the lookup table.
* $t$, the (public) **lookup table**.
* $s$, the (secret) concatenation of $f$ and $t$, sorted by $t$ (where elements are listed in the order they are listed in $t$).

Essentially, plookup proves that all the elements in $f$ are indeed in the lookup table $t$ if and only if the following multisets are equal:

* $\{(1+\beta)f, \text{diff}(t)\}$
* $\text{diff}(\text{sorted}(f, t))$

where $\text{diff}$ is a new set derived by applying a "randomized difference" between every successive pairs of a vector. For example:

* $f = \{5, 4, 1, 5\}$
* $t = \{1, 4, 5\}$
* $\{\color{blue}{(1+\beta)f}, \color{green}{\text{diff}(t)}\} = \{\color{blue}{(1+\beta)5, (1+\beta)4, (1+\beta)1, (1+\beta)5}, \color{green}{1+\beta 4, 4+\beta 5}\}$
* $\text{diff}(\text{sorted}(f, t)) = \{1+\beta 1, 1+\beta 4, 4+\beta 4, 4+\beta 5, 5+\beta 5, 5+\beta 5\}$

> Note: This assumes that the lookup table is a single column. You will see in the next section how to address lookup tables with more than one column.

The equality between the multisets can be proved with the permutation argument of plonk, which would look like enforcing constraints on the following accumulator:

* init: $acc_0 = 1$ 
* final: $acc_n = 1$
* for every $0 < i \leq n$:
    $$
    acc_i = acc_{i-1} \cdot \frac{(\gamma + (1+\beta) f_{i-1})(\gamma + t_{i-1} + \beta t_i)}{(\gamma + s_{i-1} + \beta s_{i})}
    $$
 
Note that the plookup paper uses a slightly different equation to make the proof work. I believe the proof would work with the above equation, but for simplicity let's just use the equation published in plookup:

$$
acc_i = acc_{i-1} \cdot \frac{(1+\beta)(\gamma + f_{i-1})(\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})}
$$

> Note: in plookup $s$ is too large, and so needs to be split into multiple vectors to enforce the constraint at every $i \in [[0;n]]$. We ignore this for now.

### Lookup tables

Kimchi uses a single **lookup table** at the moment of this writing; the XOR table. The XOR table for values of 1 bit is the following:


| l   | r   | o   |
| --- | --- | --- |
| 1   | 0   | 1   |
| 0   | 1   | 1   |
| 1   | 1   | 0   |
| 0   | 0   | 0   |

Whereas kimchi uses the XOR table for values of 4 bits, which has $2^{8}$ entries.

Note: the (0, 0, 0) **entry** is at the very end on purpose (as it will be used as dummy entry for rows of the witness that don't care about lookups).

### Querying the table

The plookup paper handles a vector of lookups $f$ which we do not have. So the first step is to create such a table from the witness columns (or registers). To do this, we define the following objects:

* a **query** tells us what registers, in what order, and scaled by how much, are part of a query
* a **query selector** tells us which rows are using the query. It is pretty much the same as a [gate selector]().

Let's go over the first item in this section.

For example, the following **query** tells us that we want to check if $r_0 \oplus r_2 = 2r_1$

|   l   |   r   |   o   |
| :---: | :---: | :---: |
| 1, r0 | 1, r2 | 2, r1 |

The grand product argument for the lookup consraint will look like this at this point:

$$
acc_i = acc_{i-1} \cdot \frac{\color{green}{(1+\beta)(\gamma + w_0(g^i) + j \cdot w_2(g^i) + j^2 \cdot 2 \cdot w_1(g^i))}(\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})}
$$

Not all rows need to perform queries into a lookup table. We will use a query selector in the next section to make the constraints work with this in mind.

### Query selector

The associated **query selector** tells us on which rows the query into the XOR lookup table occurs.

|  row  | query selector |
| :---: | :------------: |
|   0   |       1        |
|   1   |       0        |


Both the (XOR) lookup table and the query are built-ins in kimchi. The query selector is derived from the circuit at setup time. Currently only the ChaCha gates make use of the lookups.

The grand product argument for the lookup constraint looks like this now:

$$
acc_i = acc_{i-1} \cdot \frac{\color{green}{(1+\beta) \cdot query} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})}
$$

where $\color{green}{query}$ is constructed so that a dummy query ($0 \oplus 0 = 0$) is used on rows that don't have a query.

$$
\begin{align}
query = &\ selector \cdot (\gamma + w_0(g^i) + j \cdot w_2(g^i) + j^2 \cdot 2 \cdot w_1(g^i)) + \\
&\ (1- selector) \cdot (\gamma + 0 + j \cdot 0 + j^2 \cdot 0)
\end{align}
$$

### Queries, not query

Since we allow multiple queries per row, we define multiple **queries**, where each query is associated with a **lookup selector**. 

At the moment of this writing, the `ChaCha` gates all perform $4$ queries in a row. Thus, $4$ is trivially the largest number of queries that happen in a row.

**Important**: to make constraints work, this means that each row must make 4 queries. (Potentially some or all of them are dummy queries.)

For example, the `ChaCha0`, `ChaCha1`, and `ChaCha2` gates will apply the following 4 XOR queries on the current and following rows:

|   l   |   r   |   o    | -   |   l   |   r   |   o    | -   |   l   |   r   |   o    | -   |   l   |   r    |   o    |
| :---: | :---: | :----: | --- | :---: | :---: | :----: | --- | :---: | :---: | :----: | --- | :---: | :----: | :----: |
| 1, r3 | 1, r7 | 1, r11 | -   | 1, r4 | 1, r8 | 1, r12 | -   | 1, r5 | 1, r9 | 1, r13 | -   | 1, r6 | 1, r10 | 1, r14 |

which you can understand as checking for the current and following row that

* $r_3 \oplus r7 = r_{11}$
* $r_4 \oplus r8 = r_{12}$
* $r_5 \oplus r9 = r_{13}$
* $r_6 \oplus r10 = r_{14}$

The `ChaChaFinal` also performs $4$ (somewhat similar) queries in the XOR lookup table. In total this is 8 different queries that could be associated to 8 selector polynomials.

### Grouping queries by queries pattern

Associating each query with a selector polynomial is not necessarily efficient. To summarize:

* the `ChaCha0`, `ChaCha1`, and `ChaCha2` gates that make $4$ queries into the XOR table
* the `ChaChaFinal` gate makes $4$ different queries into the XOR table

Using the previous section's method, we'd have to use $8$ different lookup selector polynomials for each of the different $8$ queries. Since there's only $2$ use-cases, we can simply group them by **queries patterns** to reduce the number of lookup selector polynomials to $2$.

The grand product argument for the lookup constraint looks like this now:

$$
acc_i = acc_{i-1} \cdot \frac{\color{green}{(1+\beta)^4 \cdot query} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})}
$$

where $\color{green}{query}$ is constructed as:

$$
\begin{align}
query = &\ selector_1 \cdot pattern_1 + \\
&\ selector_2 \cdot pattern_2 + \\
&\ (1 - selector_1 - selector_2) \cdot (\gamma + 0 + j \cdot 0 + j^2 \cdot 0)^4
\end{align}
$$

where, for example the first pattern for the `ChaCha0`, `ChaCha1`, and `ChaCha2` gates looks like this:

$$
\begin{align}
pattern_1 = &\ (\gamma + w_3(g^i) + j \cdot w_7(g^i) + j^2 \cdot w_{11}(g^i)) \cdot \\
&\ (\gamma + w_4(g^i) + j \cdot w_8(g^i) + j^2 \cdot w_{12}(g^i)) \cdot \\
&\ (\gamma + w_5(g^i) + j \cdot w_9(g^i) + j^2 \cdot w_{13}(g^i)) \cdot \\
&\ (\gamma + w_6(g^i) + j \cdot w_{10}(g^i) + j^2 \cdot w_{14}(g^i)) \cdot \\
\end{align}
$$

Note:

* there's now 4 dummy queries, and they only appear when none of the lookup selectors are active
* if a pattern uses less than 4 queries, they'd have to pad their queries with dummy queries as well

## Back to the grand product argument

There are two things that we haven't touched on:

* The vector $t$ representing the **combined lookup table** (after its columns have been combined with a joint combiner $j$). The **non-combined loookup table** is fixed at setup time and derived based on the lookup tables used in the circuit (for now only one, the XOR lookup table, can be used in the circuit).
* The vector $s$ representing the sorted multiset of both the queries and the lookup table. This is created by the prover and sent as commitment to the verifier.

The first vector $t$ is quite straightforward to think about: 

* if it is smaller than the domain (of size $n$), then we can repeat the last entry enough times to make the table of size $n$.
* if it is larger than the domain, then we can either increase the domain or split the vector in two (or more) vectors. This is most likely what we will have to do to support multiple lookup tables later.

What about the second vector?

## The sorted vector $s$

The second vector $s$ is of size 

$$n \cdot |\text{queries}| + |\text{lookup\_table}|$$

That is, it contains the $n$ elements of each **query vectors** (the actual values being looked up, after being combined with the joint combinator, that's $4$ per row), as well as the elements of our lookup table (after being combined as well).

Because the vector $s$ is larger than the domain size $n$, it is split into several vectors of size $n$. Specifically, in the plonkup paper, the two halves of $s$ (which are then interpolated as $h_1$ and $h_2$).

$$
acc_i = acc_{i-1} \cdot \frac{\color{green}{(1+\beta)^4 \cdot query} \cdot (\gamma(1 + \beta) + t_{i-1} + \beta t_i)}{(\gamma(1+\beta) + s_{i-1} + \beta s_{i})(\gamma(1+\beta)+s_{n+i-1} + \beta s_{n+i})}
$$

Since you must compute the difference of every contiguous pairs, the last element of the first half is the replicated as the first element of the second half ($s_{n-1} = s_{n}$), and a separate constraint enforces that continuity on the interpolated polynomials $h_1$ and $h_2$: 

$$L_{n-1}(h_1(x) - h_2(g \cdot x)) = 0$$

which is equivalent with checking that

$$h_1(g^{n-1}) = h_2(1)$$

## The sorted vector $s$ in kimchi

Since this vector is known only by the prover, and is evaluated as part of the protocol, zero-knowledge must be added to the polynomial. To do this in kimchi, we use the same technique as with the other prover polynomials: we randomize the last evaluations (or rows, on the domain) of the polynomial. 

This means two things for the lookup grand product argument:

1. we cannot use the wrap around trick to make sure that the list is split in two correctly (enforced by $L_{n-1}(h_1(x) - h_2(g \cdot x)) = 0$ which is equivalent to $h_1(g^{n-1}) = h_2(1)$ in the plookup paper)
2. we have even less space to store an entire query vector. Which is actually super correct, as the witness also has some zero-knowledge rows at the end that should not be part of the queries anyway.

The first problem can be solved in two ways:

* **Zig-zag technique**. By reorganizing $s$ to alternate its values between the columns. For example, $h_1 = (s_0, s_2, s_4, \cdots)$ and $h_2 = (s_1, s_3, s_5, \cdots)$ so that you can simply write the denominator of the grand product argument as 
    $$(\gamma(1+\beta) + h_1(x) + \beta h_2(x))(\gamma(1+\beta)+ h_2(x) + \beta h_1(x \cdot g))$$
    this is what the [plonkup](https://eprint.iacr.org/2022/086) paper does. 
* **Snake technique**. by reorganizing $s$ as a snake. This is what is done in kimchi currently.

The snake technique rearranges $s$ into the following shape:

```
    _   _
 | | | | |
 | | | | |
 |_| |_| |
```

so that the denominator becomes the following equation:

$$(\gamma(1+\beta) + h_1(x) + \beta h_1(x \cdot g))(\gamma(1+\beta)+ h_2(x \cdot g) + \beta h_2(x))$$

and the snake doing a U-turn is constrained via something like

$$L_{n-1} \cdot (h_1(x) - h_2(x)) = 0$$

If there's an $h_3$ (because the table is very large, for example), then you'd have something like:

$$(\gamma(1+\beta) + h_1(x) + \beta h_1(x \cdot g))(\gamma(1+\beta)+ h_2(x \cdot g) + \beta h_2(x))\color{green}{(\gamma(1+\beta)+ h_3(x) + \beta h_3(x \cdot g))}$$

with the added U-turn constraint:

$$L_{0} \cdot (h_2(x) - h_3(x)) = 0$$

## Unsorted $t$ in $s$

Note that at setup time, $t$ cannot be sorted as it is not combined yet. Since $s$ needs to be sorted by $t$ (in other words, not sorted, but sorted following the elements of $t$), there are two solutions:

1. both the prover and the verifier can sort the combined $t$, so that $s$ can be sorted via the typical sorting algorithms
2. the prover can sort $s$ by $t$, so that the verifier doesn't have to do any sorting and can just rely on the commitment of the columns of $t$ (which the prover can evaluate in the protocol).

We do the second one, but there is an edge-case: the combined $t$ entries can repeat.
For some $i, l$ such that $i \neq l$, we might have

$$
t_0[i] + j t_1[i] + j^2 t_2[i] = t_0[l] + j t_1[l] + j^2 t_2[l]
$$

For example, if $f = \{1, 2, 2, 3\}$ and $t = \{2, 1, 2, 3\}$, then $\text{sorted}(f, t) = \{2, 2, 1, 1, 2, 3\}$ would be one way of sorting things out. But $\text{sorted}(f, t) = \{2, 2, 2, 1, 1, 3\}$ would be incorrect.


## Recap

So to recap, to create the sorted polynomials $h_i$, the prover:

1. creates a large query vector which contains the concatenation of the $4$ per-row (combined with the joint combinator) queries (that might contain dummy queries) for all rows
2. creates the (combined with the joint combinator) table vector
3. sorts all of that into a big vector $s$
4. divides that vector $s$ into as many $h_i$ vectors as a necessary following the snake method
5. interpolate these $h_i$ vectors into $h_i$ polynomials
6. commit to them, and evaluate them as part of the protocol.
