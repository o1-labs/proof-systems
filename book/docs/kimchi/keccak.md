# Keccak Gate

The Keccak gadget is comprised of 3 circuit gates (`Xor16`, `Rot64`, and `Zero`)

Keccak works with 64-bit words. The state is represented using $5\times 5$
matrix of 64 bit words. Each compression step of Keccak consists of 24 rounds.
Let us denote the state matrix with $A$ (indexing elements as $A[x,y]$), from
which we derive further states as follows in each round. Each round then
consists of the following 5 steps:

$$
\begin{aligned}
C[x] &= A[x,0] \oplus A[x,1] \oplus A[x,2] \oplus A[x,3] \oplus A[x,4] \\
D[x] &= C[x-1] \oplus ROT(C[x+1],1) \\
E[x,y] &= A[x,y]  \oplus D[x] \\
B[y,2x+3y] &= ROT(E[x,y],\rho[x,y]) \\
F[x,y] &= B[x,y] \oplus ((NOT\ B[x+1,y]) AND\ B[x+2,y]) \\
Fp[0,0] &= F[0,0] \oplus RC
\end{aligned}
$$

for $0\leq x, y \leq 4$ and $\rho[x,y]$ is the rotation offset defined for
Keccak. The values are in the table below extracted from the Keccak reference
[Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf)

|       | x = 3 | x = 4 | x = 0 | x = 1 | x = 2 |
| ----- | ----- | ----- | ----- | ----- | ----- |
| y = 2 | 155   | 231   | 3     | 10    | 171   |
| y = 1 | 55    | 276   | 36    | 300   | 6     |
| y = 0 | 28    | 91    | 0     | 1     | 190   |
| y = 4 | 120   | 78    | 210   | 66    | 253   |
| y = 3 | 21    | 136   | 105   | 45    | 15    |

## Design Approach:

The atomic operations are XOR, ROT, NOT, AND. In the sections below, we will
describe the gates for these operations. Below are some common approaches
followed in their design.

To fit within 15 wires, we first decompose each word into its lower and upper
32-bit components. A gate for an atomic operation works with those 32-bit
components at a time.

Before we describe the specific gate design approaches, below are some
constraints in the Kimchi framework that dictated those approaches.

- only 4 lookups per row
- only first 7 columns are available to the permutation polynomial

## Rot64

It is clear from the definition of the rotation gate that its constraints are
complete (meaning that honest instances always satisfy the constraints). It is
left to be proven that the proposal is sound. In this section, we will give a
proof that as soon as we perform the range checks on the excess and shifted
parts of the input, only one possible assignment satisfies the constraints. This
means that there is no dishonest instance that can make the constraints pass. We
will also give an example where one could find wrong rotation witnesses that
would satisfy the constraints if we did not check the range.

### Necessity of range checks

First of all, we will illustrate the necessity of range-checks with a simple
example. For the sake of readability, we will use some toy field lengths. In
particular, let us assume that our words have 4 bits, meaning all of the
elements between `0x0` and `0xF`. Next, we will be using the native field
$\mathbb{F}_{32}$.

As we will later see, this choice of field lengths is not enough to perform any
4-bit rotation, since the operations in the constraints would overflow the
native field. Nonetheless, it will be sufficient for our example where we will
only rotate by 1 bit.

Assume we want to rotate the word `0b1101` (meaning 13) by 1 bit to the left.
This gives us the rotated word `0b1011` (meaning 11). The excess part of the
word is `0b1`, whereas the shifted part corresponds to `0b1010`. We recall the
constraints for the rotation gate:

$$
\begin{align*}
word \cdot 2^{rot} &= excess \cdot 2^{len} + shifted \\
rotated &= excess + shifted
\end{align*}
$$

Applied to our example, this results in the following equations:

$$
\begin{align*}
13 \cdot 2 &= excess \cdot 16 + shifted \\
11 &= excess + shifted
\end{align*}
$$

We can easily check that the proposed values of the shifted `0b1010=10` and the
excess `0b1=1` values satisfy the above constraint because
$26 = 1 \cdot 16 + 10$ and $11 = 1 + 10$. Now, the question is: _can we find
another value for excess and shifted, such that their addition results in an
incorrect rotated word?_

The answer to this question is yes, due to **diophantine equations**. We
basically want to find $x,y$ such that $26 = x \cdot 16 + y (\text{ mod } 32)$.
The solution to this equation is:

$$
\begin{align*}
\forall k \in [0 \ldots 31]: x &= k \ \land \\
y &= 26 - 16 \cdot k
\end{align*}
$$

We chose these word and field lengths to better understand the behaviour of the
solution. Here, we can see two "classes" of evaluations.

- If we choose an even $k$, then $y$ will have the following shape:
  - $$26 - 16 \cdot (2 \cdot n) \iff 26 - 32n \equiv_{32} 26 $$
  - Meaning, if $x = 2n$ then $y = 26$.

- If on the other hand, we chose an odd $k$, then $y$ will have the following
  shape instead:
  - $$26 - 16 \cdot (2 \cdot n + 1) \iff 26 - 32n - 16 \equiv_{32} 26 - 16 = 10$$
  - Meaning, if $x = 2n+1$ then $y = 10$.

Thus, possible solutions to the diophantine equation are:

$$
\begin{align*}
x &= 0, 1, 2, 3, 4, 5 \ldots \\
y &= 26, 10, 26, 10, 26, 10 \ldots
\end{align*}
$$

Note that our valid witness is part of that set of solutions, meaning $x=1$ and
$y=10$. Of course, we can also find another dishonest instantiation such as
$x=0$ and $y=26$. Perhaps one could think that we do not need to worry about
this case, because the resulting rotation word would be $0+26=26$, and if we
later use that result as an input to a subsequent gate such as XOR, the value
$26$ would not fit and at some point the constraint system would complain.
Nonetheless, we still have other solutions to worry about, such as $(x=3, y=10)$
or $(x=5, y=10)$, since they would result in a rotated word that would fit in
the word length of 4 bits, yet would be incorrect (not equal to $11$).

All of the above incorrect solutions differ in one thing: they have different
bit lengths. This means that we need to range check the values for the excess
and shifted witnesses to make sure they have the correct length.

### Sufficiency of range checks

In the following, we will give a proof that performing range checks for these
values is not only necessary but also sufficient to prove that the rotation gate
is sound. In other words, we will prove there are no two possible solutions of
the decomposition constraint that have the correct bit lengths. Now, for the
sake of robustness, we will consider 64-bit words and fields with at least twice
the bit length of the words (as is our case).

We will proceed by **contradiction**. Suppose there are two different solutions
to the following diophantic equation:

$$
\begin{align*}
\forall k \in \mathbb{F}_n: x &= k \ \land \\
y &= w \cdot 2^r - 2^{64} \cdot k
\end{align*}
$$

where $k$ is a parameter to instantiate the solutions, $w$ is the word to be
rotated, $r$ is the rotation amount, and $n$ is the field length.

Then, that means that there are two different solutions,
$(0\leq x=a<2^r, 0\leq y=b<2^{64})$ and $(0\leq x=a'<2^r, 0\leq y=b'<2^{64})$
with at least $a \neq a'$ or $b \neq b'$. We will show that this is impossible.

If both are solutions to the same equation, then:

$$
\begin{align*}
w \cdot 2^r &= a \cdot 2^{64} + b \\
w \cdot 2^r &= a'\cdot 2^{64} + b'
\end{align*}
$$

means that $a \cdot 2^{64} + b = a'\cdot 2^{64} + b'$. Moving terms to the left
side, we have an equivalent equality: $2^{64}(a-a') + (b-b')=0 \mod{n}$. There
are three cases to consider:

- $a = a'$ and $b \neq b'$: then $(b - b') \equiv_n 0$ and this can only happen
  if $b' = b + kn$. But since $n > 2^{64}$, then $b'$ cannot be smaller than
  $2^{64}$ as it was assumed. CONTRADICTION.

- $b = b'$ and $a \neq a'$: then $2^{64}(a - a') \equiv_n 0$ and this can only
  happen if $a' = a + kn$. But since $n > 2^r$, then $a'$ cannot be smaller than
  $2^r$ as it was assumed. CONTRADICTION.

- $a\neq a'$ and $b \neq b'$: then we have something like
  $2^{64} \alpha + \beta \equiv_n 0$.
  - This means $\beta \equiv_n -2^{64} \alpha = k \cdot n - 2^{64} \alpha$ for
    any $k$.
  - According to the assumption, both $0\leq a<2^r$ and $0\leq a'<2^r$. This
    means, the difference $\alpha:=(a - a')$ lies anywhere in between the
    following interval: $$1 - 2^r \leq \alpha \leq 2^r - 1$$
  - We plug in this interval to the above equation to obtain the following
    interval for $\beta$:
    $$k\cdot n - 2^{64}(1-2^r)\leq \beta \leq k\cdot n - 2^{64}(2^r - 1) $$
  - We look at this interval from both sides of the inequality:
    $\beta \geq kn - 2^{64} + 2^{64+r}$ and $\beta \leq kn + 2^{64} - 2^{64+r}$
    and we wonder if $kn - 2^{64} + 2^{64+r} \leq kn + 2^{64} - 2^{64+r}$ is at
    all possible. We rewrite as follows:
    $$
    \begin{align*}
     2^{64+r} - 2^{64} &\leq 2^{64} - 2^{64+r}\\
     2\cdot2^{64+r} &\leq 2\cdot2^{64} \\
     2^{64+r} &\leq 2^{64}
     \end{align*}
    $$
  - But this can only happen if $r\leq 0$, which is impossible since we assume
    $0 < r < 64$. CONTRADICTION.
- EOP.
