# Commitments

A "commitment scheme" is a cryptographic scheme that lets us provide a "commitment" to a given piece of data, in such a way that we can later "open" that commitment.

I recommend checking out section 2.4.1 of David's book Real-World Cryptography. There are two properties we typically expect of our commitment schemes:

- **Hiding.** A commitment to a piece of data should not reveal anything about that data.

- **Binding.** There should be no ambiguity about what data is committed to. That is, it should not be possible for the committer to open the commitment to a piece of data other than the one they originally committed to.

There are various kinds of commitments that allow opening in different ways, revealing only part of the data, or some function of the data.

## Simple commitments

The simplest kind of a commitment is one in which opening reveals all of the underlying data. Let's give a simple construction of such a scheme for committing to field elements. Suppose we have

- $\mathbb{F}_p$ a prime order field, with $p$ being rather large (say on the order of $2^{256}$).

- A hash function $h \colon \mathsf{List}(\mathbb{F}_p) \to \mathbb{F}_p$.

Then we define

$$
\mathsf{commit}(x, r) = h([x, r]) \\
\mathsf{open}(x, r) = (x, r)
$$

The second argument of the $\mathsf{commit}$ and $\mathsf{open}$ function is data that is known only to the committer. When a committer wants to commit to a field element $x$, they sample a random "blinder" $r \in \mathbb{F}_p$ and hash it together with $x$ to form the committment.

To open, they simply provide the commited value together with the blinder.

If the hash function is collision-resistant, then this function is binding (because there's no way the comitter could find another preimage of $h([x, r])$).

If the hash function is one-way, then this commitment is also hiding.

## Polynomial commitments

To construct SNARKs we use use polynomial commitments. A **polynomial commitment scheme**  for a field $F$ (or it could even be a ring) is a way of commiting to a polynomial $f \in F[x]$ to get a commitment $c$, in such a way that for any $\alpha \in F$, you can provide $y = f(\alpha)$, along with an "opening proof" $\pi$ that proves that the polynomial committed to in $c$ equals $y$ when evaluated at $\alpha$.

In other words, it is a type of commitments $C$, a type of randomness $R$, a type of opening proof $P$ along with algorithms

$$
\mathsf{commit} \colon F[x] \times R \to C \\
\mathsf{open} \colon C \times F \times (F[x] \times R) \to F \times P \\
\mathsf{verify} \colon C \times (F \times P) \to \mathsf{Bool}
$$

such that for any $f \in F[x],\; r \in R,\; a \in F$ , we have

$$
c := \mathsf{commit}(f, r) \\
\mathsf{verify}(c, \mathsf{open}(c, a, (f, r))) = \mathsf{true}
$$

and if $b \neq f(a)$ then it is not possible to compute $\pi \in P$ such that

$$
\mathsf{verify}(c, (b, \pi)) = \mathsf{true}
$$

In other words, if $b \neq f(a)$ then every $\pi$ which is feasible to compute results in $\mathsf{verify}(c, (b, \pi)) = \mathsf{false}$.

> One thing that's pretty cool is that because polynomial commitment schemes let you construct zk-SNARKs, polynomial commitment schemes imply commitment schemes with arbitrary opening functionality. TODO

### Constructing polynomial commitment schemes

All known constructions of polynomial commitment schemes are a bit complicated. The easiest to describe is called the Kate (pronounced "kah-TAY") scheme, also known as "KZG". It requires a "prime-order group with a pairing", which is three groups $G_1, G_2, G_T$ of prime order $p$ (hence, all isomorphic cyclic groups) together with a function $e \colon G_1 \times G_2 \to G_T$ such that for any $a_1, a_2 \in \Z$, $g_1 \in G_1$, $g_2 \in G_2$, we have

$$
e(a_1 \cdot g_1, a_2 \cdot g_2) = a_1 a_2 \cdot e(g_1, g_2)
$$

$e$ is called a "pairing" or a "bilinear pairing". What this lets us do is "multiply in the scalar" but only once.

Fix a degree bound $d$ on the polynomials we would like to be able to commit to. The KZG scheme, will let us commit to polynomials in $\mathbb{F}_p[x]_{< d}$. As a preliminary, fix generators $g_1 \in G_1, g_2 \in G_2$ arbitrarily.

The first thing to know about the KZG scheme is it requires that we randomly sample some group elements to help us. This is the dreaded and much discussed **trusted setup**. So, anyway, we start by sampling $\tau$ at random from $\mathbb{F}_p$ and computing for $i < d$,

$$
h_{i} := (\tau^i) \cdot g_1 \\
w := \tau \cdot g_2 
$$

And then **throw away $\tau$**. The security depends on no-one knowing this value. Basically we compute the generator scaled by powers of $\tau$ up to the degree bound. We make a security assumption about the groups which says that all anyone can really do with group elements is take linear combinations of them. 

Now suppose we have a polynomial $f \in \mathbb{F}_p[x]_{<d}$ with $f = \sum_{i < d} a_i x^i$ that we would like to commit to. We will describe a version of the scheme that is binding but not hiding, so it may leak information about the polynomial. Now, to commit to $f$, we compute

$$
c_f := a_0 \cdot h_{0} + a_1 \cdot h_{1} + \dots + a_{d-1} \cdot h_{d-1}
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

So $c$ is $g_1$ scaled by $f(\tau)$ and the fact that $G_1$ is an $\mathbb{F}_p$-module means we can compute $f(\tau) \cdot g_1$ from the $h_{i}$ and the coefficients of $f$ without knowing $\tau$.

Now how does opening work? Well, say we want to open at a point $a$ to $b = f(a)$. Then the polynomial $f - b$ vanishes at $a$, which means that it is divisible by the polynomial $x - a$ (exercise, use polynomial division and analyze the remainder).

So, the opener can compute the polynomial

$$
q := \frac{f - b}{x - a}
$$

and commit to it as above to get a commitment $c_q$. And $c_q$ will be the opening proof. It remains only to describe verification. It works like this

$$
\mathsf{verify}(c_f, (b, c_q)) := e(c_q, w - a \cdot g_2)=_? e(c_f, g_2)
$$

This amounts to checking "is the polynomial committed to $c_f$ equal to the polynomial committed to by $c_q$ times $x - a$"?To see why, remember that $w = \tau \cdot g_2$, and say $c_q = s_q\cdot g_1$, $c_f = s_f \cdot g_1$ so we are checking

$$
e(s_q \cdot g_1, (\tau - a) \cdot g_2) =_? e(s_f \cdot g_1, g_2)
$$

which by the bilinearity of the pairing is the same as checking

$$
s_q \cdot (\tau - a) = s_f
$$

## Bootleproof inner product argument
