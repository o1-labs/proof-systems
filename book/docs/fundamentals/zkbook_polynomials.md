---
title: Polynomials
---

## Polynomials

The next object to know about is polynomials. A polynomial is a syntactic object
that also defines a function.

Specifically, let $R$ be a field (or more generally it could even be a ring,
which is like a field but without necessarily having division, like the integers
$\mathbb{Z}$). And pick a variable name like $x$. Then $R[x]$ (pronounced, "R
adjoin x" or "polynomials in x over R" or "polynomials in x with R
coefficients") is the set of syntactic expressions of the form

$$a_0 + a_1 x + a_2 x^2 + \dots + a_d x^d$$

where each $a_i \in R$ and $d$ is any natural number. If we wanted to be very
formal about it, we could define $R[x]$ to be the set of lists of elements of
$R$ (the lists of coefficients), and the above is just a suggestive way of
writing that list.

An important fact about polynomials over $R$ is that they can be interpreted as
functions $R \to R$. In other words, there is a function
$\mathsf{eval} \colon R[x] \to (R \to R)$ defined by

$$
\mathsf{eval}(a_0 + a_1 x + \dots + a_d x^d) = (y \colon R) \mapsto a_0 + a_1 y + \dots + a_d y^d
$$

where $x$ is just a variable name without a value assigned to it and
$\mathsf{eval}$ maps it to a field element $y$ and evaluates the function as the
inner product between the list of coefficients and the powers of $y$.

It is important to remember that polynomials are different than the functions
that they compute. Polynomials are really just lists of coefficients. Over some
fields, there are polynomials $p1$ and $p2$ such that
$\mathsf{eval}(p1) = \mathsf{eval}(p2)$, but $p1 \neq p2$.

For example, consider in $\mathbb{F}_2[x]$ the polynomials $x$ and $x^2$. These
map to the same function $\mathbb{F}_2 \to \mathbb{F}_2$ (meaning for
$x\in R = \mathbb{F}_2=\{0,1\}$ it holds that $x=x^2$), but are distinct
polynomials.

#### Some definitions and notation

If $f$ is a polynomial in $R[x]$ and $a \in R$, we write $f(a)$ for
$\mathsf{eval}(f)(a)$

If $f$ is a polynomial, the degree of $f$ is the largest $d$ for which the
coefficient of $x^d$ is non-zero in $f$. For example, the degree of
$x^3 + 2 x^{10}$ is 10.

We will use the notation $R[x]_{< d}$ and $R[x]_{\leq d}$ for the set of
polynomials of degree _less-than_ and _less-than-or-equal_ $d$ respectively.

Polynomials can be added (by adding the coefficients) and multiplied (by
carrying out the multiplication formally and collecting like terms to reduce to
a list of coefficients). Thus $R[x]$ is a ring.

### Fundamental theorem of polynomials

An important fact for zk-SNARKs about polynomials is that we can use them to
encode arrays of field elements. In other words, there is a way of converting
between polynomials of degree $d$ and arrays of field elements of length
$d + 1$.

This is important for a few reasons

- It will allow us to translate statements about arrays of field elements into
  statements about polynomials, which will let us construct zk-SNARKs.

- It will allow us to perform certain operations on polynomials more
  efficiently.

So let's get to defining and proving this connection between arrays of field
elements.

The first thing to understand is that we won't be talking about arrays directly
in this section. Instead, we'll be talking about functions $A \to F$ where $A$
is a finite subset of $F$. The idea is, if $A$ has size $n$, and we put an
ordering on $A$, then we can think of a function $A \to F$ as the same thing as
an immutable array of length $n$, since such a function can be thought of as
returning the value of an array at the input position.

With this understanding in hand, we can start describing the "fundamental
theorem of polynomials". If $A \subseteq F$ has size $d + 1$, this theorem will
define an isomorphism between functions $A \to F$ and $F[x]_{\leq d}$, the set
of polynomials of degree at most $d$.

Now let's start defining this isomorphism.

One direction of it is very easy to define. It is none other than the evaluation
map, restricted to $A$:

$$
\begin{aligned}
\mathsf{eval}_A &\colon F[x]_{\leq d} \to (A \to F) \\
\mathsf{eval}_A&(c_0 + \dots + c_d x^d) = a \mapsto \sum_{i \leq d} c_i a^i
\end{aligned}
$$

We would now like to construct an inverse to this map. What would that mean? It
would be a function that takes as input a function $\varphi \colon A \to F$
(remember, basically an array of length $|A|$), and returns a polynomial $f$
which agrees with $\varphi$ on the set $A$. In other words, we want to construct
a polynomial that interpolates between the points $(a, \varphi(a))$ for
$a \in A$.

Our strategy for constructing this polynomial will be straightforward. For each
$a \in A$, we will construct a polynomial $f_a$ that is equal to $\varphi(a)$
when evaluated at $a$, and equal to $0$ when evaluated anywhere else in the set
$A$.

Then, our final polynomial will be $f := \sum_{a \in A} f_a$. Then, when $f$ is
evaluated at $a_0 \in A$, only the $f_{a_0}$ term will be non-zero (and equal to
$\varphi(a_0)$ as desired), all the other terms will disappear.

Constructing the interpolation map requires a lemma.

> **Lemma.** (construction of vanishing polynomials)
>
> Let $S \subseteq F$. Then there is a polynomial $v_S \in F[x]$ of degree $|S|$
> such that $v_S$ evaluates to $0$ on $S$, and is non-zero off of $S$. $v_S$ is
> called the vanishing polynomial of $S$.

**Proof.** Let $v_S = \prod_{s \in S} (x - s)$. Clearly $v_S$ has degree $|S|$.
If $t \in S$, then $v_S(t) = 0$ since $x - t$ is one of the terms in the product
defining $v_S$, so when we evaluate at $t$, $t - t = 0$ is one of the terms. If
$t \notin S$, then all the terms in the product are non-zero, and thus $v_S(t)$
is non-zero as well. $\square$

Now we can define the inverse map. Define

$$
\begin{aligned}
\mathsf{interp}_A &\colon (A \to F) \to F[x]_{\leq d} \\
\mathsf{interp}_A & (f) = \sum_{a \in A} \frac{f(a)}{v_{A \setminus \{a \}}(a) } \cdot v_{A \setminus \{ a \} }
\end{aligned}
$$

Since each $v_{A \setminus \{a \} }$ has degree $d$, this polynomial has degree
$d$. Now we have, for any $b \in A$,

$$
\begin{aligned}
 \mathsf{eval}_A(\mathsf{interp}_A(f))(b)
&=\sum_{a \in A} \frac{f(a)}
{v_{A \setminus \{a \}}(a) } \cdot
v_{A \setminus \{ a \}}(b) \\
&=
\frac{f(b)}
{v_{A \setminus \{b \}}(b) } \cdot
v_{A \setminus \{ b \}}(b)
+ \sum_{a \neq b} \frac{f(a)}
{v_{A \setminus \{a \}}(a) } \cdot
v_{A \setminus \{ a \} }(b) \\
&=
f(b    )
+ \sum_{a \neq b} \frac{f(a)}
{v_{A \setminus \{a \}}(a) } \cdot
0 \\
&= f(b)
\end{aligned}
$$

Thus $\mathsf{eval}_A \circ \mathsf{interp}_A$ is the identity.

So we have successfully devised a way of interpolating a set of $d + 1$ points
with a polynomial of degree $d$.

What remains to be seen is that these two maps are inverse in the other
direction. That is, that for any polynomial $f \in F[x]$, we have

$$
\mathsf{interp}_A(\mathsf{eval}_A(f)) = f
$$

This says that if we interpolate the function that has the values of $f$ on $A$,
we get back $f$ itself. This essentially says that there is only one way to
interpolate a set of $d + 1$ points with a degree $d$ polynomial. So let's prove
it by proving that statement.

> **Lemma: polynomials that agree on enough points are equal.**
>
> Let $F$ be a field and suppose $f, g \in F[x]$ have degree at most $d$. Let
> $A \subseteq F$ have size $d + 1$.
>
> Suppose for all $a \in A$, $f(a) = g(a)$. Then $f = g$ as polynomials.

**Proof.** Define $h := f - g$. Our strategy will be to show that $h$ is the
zero polynomial. This would then imply that $f = g$ as polynomials. Note that
$h$ vanishes on all of $A$ since $f$ and $g$ are equal on $A$.

To that end, let $a \in A$. Then we can apply the polynomial division algorithm
to divide $h$ by $x - a$ and obtain polynomials $q_a, r_a$ such that
$h = q_a (x - a) + r_a$ and $r_a$ has degree less than 1. I.e., $r_a$ is a
constant in $F$.

Now,

$$
0 = h(a) = q_a(a) \cdot 0 + r_a = r_a
$$

so $r_a = 0$ and thus $h = q_a (x - a)$.

Note that $q_a$ is 0 on all elements $b \in A$ with $b \neq a$ since
$h(b) = q_a(b) (b - a) = 0$, but $b - a \neq 0$.

Thus, if we iterate the above, enumerating the elements of $A$ as
$a_0, \dots, a_d$, we find that

$$
\begin{aligned}
h &= (x - a_0) q_{a_0} \\
&= (x - a_0) (x - a_1) q_{a_1} \\
&= \dots \\
&= (x - a_0) (x - a_1) \dots (x - a_d) q_{a_d}
\end{aligned}
$$

Now, if $q_{a_d}$ is not the zero polynomial, then $h$ will have degree at least
$d + 1$ since it would have as a factor the $d + 1$ linear terms $(x - a_i)$.
But since $f, g$ both have degree at most $d$ and $h = f - g$, $h$ has degree at
most $d$ as well. Thus, $q_{a_d} = 0$, which means $h = 0$ as well.

This gives us the desired conclusion, that $f = g$ as polynomials. $\square$

Now we can easily show that interpolating the evaluations of a polynomial yields
that polynomial itself. Let $f \in F[x]_{\leq d}$. Then
$\mathsf{interp}_A(\mathsf{eval}_A(f))$ is a polynomial of degree at most $d$
that agrees with $f$ on $A$, a set of size $d + 1$. Thus, by the lemma, they are
equal as polynomials. So indeed

$$
\mathsf{interp}_A(\mathsf{eval}_A(f)) = f
$$

for all $f \in F[x]$.

So far we have proven that $\mathsf{interp}_A$ and $\mathsf{eval}_A$ give an
isomorphism of sets (i.e., a bijection) between the sets $A \to F$ and
$F[x]_{\leq d}$.

But we can take this theorem a bit further. The set of functions $A \to F$ can
be given the structure of a ring, where addition and multiplication happen
pointwise. I.e., for $f, g \colon A \to F$ we define
$f + g := a \mapsto f(a) + g(a)$ and $f \cdot g := a \mapsto f(a) \cdot g(a)$.
Then we can strengthen our theorem to say

> **Fundamental theorem of polynomials (final version)**
>
> Let $d \in \N$ and let $A \subseteq F$ with $|A| = d + 1$. With
>
> $$
>  \mathsf{eval}_A \colon F[x]_{\leq d} \to (A \to F)\\
> \mathsf{interp}_A \colon (A \to F) \to F[x]_{\leq d}
> $$

$$
>
> defined as above, these two functions define an isomorphism of rings.
>
> That is, they are mutually inverse and each one respects addition, subtraction and multiplication.

The fundamental theorem of polynomials is very important when it comes to computing operations on polynomials.
As we will see in the [next section](./zkbook_fft.md), the theorem will help us to compute the product of degree $n$ polynomials in time $O(n \log n)$, whereas the naive algorithm takes time $O(n^2)$. To put this in perspective, if $n = 2^{16}$, $n^2$ is $4096$ times larger than $n \log n$ and the gap only gets bigger as $n$ grows.

### Schwartz--Zippel lemma

### Computer representation

There are three common representations for polynomials used in computer implementations.

1. Dense coefficient form. A degree $d$ polynomial is represented as a vector of length $d + 1$ of all the coefficients. Entry $i$ of the vector corresponds to the coefficient $a_i$. This corresponds to the `DensePolynomial` type in arkworks. Sometimes this is also described as writing the polynomial "in the monomial basis", because it amounts to writing the polynomial as a linear combination of the monomials $x^i$.

2. Sparse coefficient form. If a polynomial does not have very many non-zero coefficients, the above representation is wasteful. In sparse coefficient form, you represent a polynomial as a vector (or potentially a hash-map) of pairs `(usize, F)` where `F` is the type of coefficients. The polynomial corresponding to the list `[(i_0, b_0), ..., (i_n, b_n)]` is $b_0 x^{i_0} + \dots + b_n x^{i_n}$

3. Evaluation form. We fix an index set $A \subseteq F$, with $A = \{ a_0, \dots, a_d \}$, and represent a polynomial $f \in F[x]_{\leq d}$ as the vector
   `[f(a_0), ..., f(a_d)]`. By the fundamental theorem of polynomials, this is a valid way of representing the polynomials, since the coefficients form can
   be obtained by using the $\mathsf{interp}_A$ function.

The evaluation form is very important. The reason is that multiplying two polynomials in the evaluation form takes time $O(n)$.
You just multiply the two vectors entry-wise. By contrast, the coefficient forms naively require time $O(n^2)$ to multiply.

Now, there is a trick. For certain sets $A \subseteq F$, we can efficiently translate between the dense coefficients form and the evaluation form.
That is, for certain $A$, the functions $\mathsf{interp}_A$ and $\mathsf{eval}_A$ can be computed more efficiently than $O(n^2)$.
$$
