# Commitments

## What's a commitment

A commitment is a cryptographic primitive that allows you to lock "something" (perhaps a number) without revealing it (yet). This will produce a **commitment**. Later, someone can ask you to reveal the "something". After you do, then can verify that it is linked to the commitment by **opening** it.

<img src="../../img/commitment.png" width="300px">

Commitments are usually defined with these two properties:

* **hiding**: it does not reveal what is commited
* **binding**: you can't open a commitment to a different value (think second pre-image)

## A simple example

Take a hash function, for example SHA-256, and produce a random bytearray `r` of 16 bytes.
To commit to an input, perform the following (where `||` represents concatenation):

```
commit(input) = SHA-256(r || input)
```

To open the commitment, simply reveal `input` and `r`. The opening can be performed by simply re-hashing `r || input` and observing if it is equal to the commitment.

## Why we use commitments

In most of our zero-knowledge proofs we'll deal with commitments instead of values, because we want zero-knowledge.
These commitments are given to us via the blockchain. (TODO: examples?)

## Algebraic and homomorphic commitments

These commitments are also algebraic (not using a hash function like SHA-3) and as such have **homomorphic** properties: you can add commitments together to form another commitment of the added committed values. For example, if you have $A = com(a)$ and $B = com(b)$, you can perform:

$$
A + B = com(a) + com(b) = com(a + b)
$$

## Pedersen commitments

For an input $x$, and two bases $G$ and $H$ of unknown discrete logarithm in an additive group, a pedersen commitment is computed as $xG + rH$ with randomness $r$. To open such a commitment, just reveal the value $x$ and $r$.

Note that the commitment relies on the discrete logarithm assumption, so in theory you might be lucky (or have a quantum computer) and figure out that $H = hG$, which would allow you to find different values $x'$ and $h'$ to open the commitment. We say that pedersen commitments are **computationally binding** and not unconditionally binding.
For example, you could express $c = xG + rH$ alternatively as $c = xG + rh G = (x + rh) G$ and compute a satisfying opening pair $x' = xh$ and $r' = \frac{x}{h}$.

On the other hand, Pedersen commitments are **unconditionally hiding**, as there is no way even with a magic computer to reveal what is $x$ without knowing $r$.
This is the reason why most of the proofs we will see later are not "proofs" per se, but **arguments** of knowledge (although we will care little about this distinction). In theory, you need perfect binding to be called a proof.

## Multi-commitments

We can commit to several values $x_1, \cdots, x_k$ by sending the pedersen commitments of all of these values as such:

$$ x_1 G + r_1 H, \cdots, x_k G + r_k H $$

But we can instead batch/aggregate all of these commitments together as:

$$ r H + x_1 G_1 + \cdots + x_k G_k $$

with $G_1, \cdots, G_k, H$ independent bases with unknown discrete logarithms. If you remove the $rH$ term you get a non-hiding commitment, also called a **Pedersen hash**.

Note that if you see the $x$s and the $G$s as two vectors $\vec{x} = (x_1, \cdots, x_k)$ and $\vec{G} = (G_1, \cdots, G_k)$, we can quickly write the previous statement as an inner product $\vec{x}\vec{G} + rH$.
