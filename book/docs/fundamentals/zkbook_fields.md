# Intro

The purpose of this document is to give the reader mathematical, cryptographic,
and programming context sufficient to become an effective practitioner of
zero-knowledge proofs and ZK-SNARKs specifically.

# Some fundamental mathematical objects

In this section we'll discuss the fundamental objects used in the construction
of most ZK-SNARKs in use today. These objects are used extensively and without
ceremony, so it's important to understand them very well.

If you find you don't understand something at first, don't worry: practice is
often the best teacher and in using these objects you will find they will become
like the bicycle you've had for years: like an extension of yourself that you
use without a thought.

## Fields

A field is a generalization of the concept of a number. To be precise, a field
is a set $F$ equipped with

- An element $0 \in F$

- An element $1 \in F$

- A function $\mathsf{mul} \colon F \times F \to F$

- A function $\mathsf{add} \colon F \times F \to F$

- A function $\mathsf{sub} \colon F \times F \to F$

- A function $\mathsf{div} \colon F \times (F \setminus \{ 0 \}) \to F$

Note that the second argument to $\mathsf{div}$ cannot be $0$. We write these
functions in the traditional infix notation writing

- $xy$ or $x \cdot y$ for $\mathsf{mul}(x, y)$

- $x + y$ for $\mathsf{add}(x, y)$

- $x - y$ for $\mathsf{sub}(x, y)$

- $\frac{x}{y}$ for $\mathsf{div}(x, y)$

and we also write $x^{-1}$ for $\mathsf{div}(1, x)$ and $-x$ for
$\mathsf{sub}(0, x)$.

Moreover all these elements and functions must obey all the usual laws of
arithmetic, such as

- $x + (y + z) = (x + y) + z$

- $x + y = y + x$

- $x + (- x) = 0$

- $x + 0 = x$

- $x (yz) = (x y)z$

- $x y = y x$

- $\frac{x}{y} = z$ if and only if $x = z y$, assuming $y \neq 0$.

- $1 \cdot x = x$

- $x (y + z) = xy + xz$

In short, $F$ should be an abelian group over $+$ with $0$ as identity and
$\mathsf{sub}(0, -)$ as inverse, $F \setminus \{0 \}$ should be an abelian group
over $\cdot$ with $1$ as identity and $\mathsf{div}(1, -)$ as inverse, and
addition should distribute over multiplication. If you don't know what an
abelian group is, don't worry, we will cover it later.

The point of defining a field is that we can algebraically manipulate elements
of a field the same way we do with ordinary numbers, adding, multiplying,
subtracting, and dividing them without worrying about rounding, underflows,
overflows, etc.

> In Rust, we use the trait `Field` to represent types that are fields. So, if
> we have `T : Field` then values of type `T` can be multiplied, subtracted,
> divided, etc.

### Examples

The most familiar examples of fields are the real numbers $\mathbb{R}$ and the
rational numbers $\mathbb{Q}$ (ratios of integers). Some readers may also be
friends with the complex numbers $\mathbb{C}$ which are also a field.

The fields that we use in ZKPs, however, are different. They are **finite
fields**. A **finite field** is a field with finitely many elements. This is in
distinction to the fields $\mathbb{Q}, \mathbb{R}$, and $\mathbb{C}$, which all
have infinitely many elements.

#### What are finite fields like?

In this section we'll try to figure out from first principles what a finite
field should look like. If you just want to know the answer, feel free to skip
to the next section.

Let's explore what a finite field can possibly be like. Say $F$ is a finite
field. If $n$ is a natural number like $4$ or $87$ we can imagine it as an
element of $F$ by writing $\underbrace{1 + \dots + 1}_{n}$.

Since $F$ is finite it must be the case that we can find two distinct natural
numbers $n < m$ which are the same when interpreted as elements of $F$.

Then, $m - n = 0$, which means the $F$ element
$\underbrace{1 + \dots + 1}_{m - n}$ is $0$. Now that we have established that
**if you add $1$ to itself enough times you get $0$**, let $p$ be the least
natural number such that if you add $1$ to itself $p$ times you get $0$.

Now let's show that **$p$ is prime**. Suppose it's not, and $p = a b$. Then
since $p = 0$ in $F$, $ab = 0$. It is a fact about fields (exercise) that if
$a b = 0$ then either $a$ is 0 or $b$ is 0. Either way, we would then get a
natural number smaller than $p$ which is equal to $0$ in $F$, which is not
possible since $p$ is the smallest such number. So we have demonstrated that $p$
is prime.

The smallest number of times you have to add $1$ to itself to get 0 is called
the **characteristic** of the field $F$. So, we have established that **every
finite field has a characteristic and it is prime.**

This gives us a big hint as to what finite fields should look like.

#### Prime order fields

With the above in hand, we are ready to define the simplest finite fields, which
are fields of prime order (also called prime order fields).

Let $p$ be a prime. Then $\mathbb{F}_p$ (pronounced "eff pee" or "the field of
order p") is defined as the field whose elements are the set of natural numbers
$\{ 0, 1, \dots, p - 1\}$.

- $0$ is defined to be $0$

- $1$ is defined to be $1$

- $\mathsf{add}(x, y) = (x + y) \mod p$

- $\mathsf{sub}(x, y) = (x - y) \mod p$

- $\mathsf{mul}(x, y) = (x \cdot y) \mod p$

- $\mathsf{div}(x, y) = (x \cdot y^{p - 2}) \mod p$

Basically, you just do arithmetic operations normally, except you take the
remainder after dividing by $p$. This is with the exception of division which
has a funny definition. Actually, a more efficient algorithm is used in practice
to calculate division, but the above is the most succinct way of writing it
down.

If you want, you can try to prove that the above definition of division makes
the required equations hold, but we will not do that here.

Let's work out a few examples.

2 is a prime, so there is a field $\mathbb{F}_2$ whose elements are
$\{ 0, 1 \}$. The only surprising equation we have is

- $1 + 1 = 0$

Addition is XOR and multiplication is AND.

Let's do a more interesting example. 5 is a prime, so there is a field whose
elements are $\{0,1,2,3,4\}$. We have

$$
\begin{aligned}
\frac{1}{2} &= 1 \cdot 2^{5 - 2} \\
&= 2^3 \\
&= 8 \\
&= 3
\end{aligned}
$$

where the last equality follows because everything is mod 5.

We can confirm that 3 is in fact $\frac{1}{2}$ by multiplying 3 and 2 and
checking the result is 1.

$$
\frac{1}{2} \cdot 2 = 3 \cdot 2 = 6 = 1
$$

so that checks out.

In cryptography, we typically work with much larger finite fields. There are two
ways to get a large finite field.

1. Pick a large prime $p$ and take the field $\mathbb{F}_p$. This is what we do
   in Mina, where we use fields in which $p$ is on the order of $2^{255}$.

2. Take an **extension** of a small finite field. We may expand this document to
   talk about field extensions later, but it does not now.

### Algorithmics of prime order fields

For a finite field $\mathbb{F}_p$ where $p$ fits in $n$ bits (i.e., $p < 2^n$)
we have

- Addition, subtraction: $O(n)$

- Multiplication $O(n^2)$

- Division $O(n^2)$ I believe, in practice significantly slower than
  multiplication.

Actually, on a practical level, it's more accurate to model the complexity in
terms of the number of _limbs_ rather than the number of bits where a limb is 64
bits. Asymptotically it makes no difference but concretely it's better to think
about the number of limbs for the most part.

As a result you can see it's the smaller $n$ is the better, especially with
respect to multiplication, which dominates performance considerations for
implementations of zk-SNARKs, since they are dominated by elliptic curve
operations that consist of field operations.

While still in development, Mina used to use a field of 753 bits or 12 limbs and
now uses a field of 255 bits or 4 limbs. As a result, field multiplication
became automatically sped up by a factor of $12^2 / 4^2 = 9$, so you can see
it's very useful to try to shrink the field size.
