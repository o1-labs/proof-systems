# Foreign Field Addition RFC

This document is meant to explain the foreign field addition gate in Kimchi.

## Overview

The goal of this gate is to perform the following operation between a left $a$
and a right $b$ input, to obtain a result $r$ $$a + s \cdot b = r \mod f$$ where
$a,b,r\in\mathbb{F}_f$ belong to the _foreign field_ $\mathbb{F}_f$ of modulus
$f$ and we work over a native field $\mathbb{F}_n$ of modulus $n$, and
$s \in \{-1, 1\}$ is a flag indicating whether it is a subtraction or addition
gate.

If $f < 2 \cdot n$ then we can easily perform the above computation natively
since no overflows happen. But in this gate we are interested in the contrary
case in which $f>n$. In order to deal with this, we will divide foreign field
elements into limbs that fit in our native field. We want to be compatible with
the foreign field multiplication gate, and thus the parameters we will be using
are the following:

- 3 limbs of 88 bits each (for a total of 264 bits)
- So $f < 2^{264}$, concretely:
  - The modulus $f$ of the foreign field $\mathbb{F}_f$ is 256 bit
  - The modulus of our the native field $\mathbb{F}_n$ is 255 bit

In other words, using 3 limbs of 88 bits each allows us to represent any foreign
field element in the range $[0,2^{264})$ for foreign field addition, but only up
to $2^{259}$ for foreign field multiplication. Thus, with the current
configuration of our limbs, our foreign field must be smaller than $2^{259}$
(because $2^{264} \cdot 2^{255} > {2^{259}}^2 + 2^{259}$, more on this in
[Foreign Field Multiplication](../kimchi/foreign_field_mul.md) or the original
[FFmul RFC](https://github.com/o1-labs/rfcs/blob/main/0006-ffmul-revised.md).

### Splitting the addition

Let's take a closer look at what we have, if we split our variables in limbs
(using little endian)

```text
bits  0..............87|88...........175|176...........263

a  =  (-------a0-------|-------a1-------|-------a2-------)
+/-
b  =  (-------b0-------|-------b1-------|-------b2-------)
=
r  =  (-------r0-------|-------r1-------|-------r2-------)  mod(f)
```

We will perform the addition in 3 steps, one per limb. Now, when we split long
additions in this way, we must be careful with carry bits between limbs. Also,
even if $a$ and $b$ are foreign field elements, it could be the case that
$a + b$ is already larger than the modulus (in this case $a + b$ could be at
most $2f - 2$). But it could also be the case that the subtraction produces an
underflow because $a < b$ (with a difference of at most $1 - f$). Thus we will
have to consider the more general case. That is,

$$ a + s \cdot b = q \cdot f + r \mod 2^{264}$$

with a field overflow term $q \in \{-1,0,1\}$ that will be either $0$ (if no
underflow nor overflow is produced), $1$ (if there is overflow with $s = 1$) or
$-1$ (if there is underflow with $s = -1$). Looking at this in limb form, we
have:

```text
bits  0..............87|88...........175|176...........263

a  =  (-------a0-------|-------a1-------|-------a2-------)
+
s = 1 | -1
·
b  =  (-------b0-------|-------b1-------|-------b2-------)
=
q  =  -1 | 0 | 1
·
f  =  (-------f0-------|-------f1-------|-------f2-------)
+
r  =  (-------r0-------|-------r1-------|-------r2-------)
```

First, if $a + b$ is larger than $f$, then we will have a field overflow
(represented by $q = 1$) and thus will have to subtract $f$ from the sum $a + b$
to obtain $r$. Whereas the foreign field overflow necessitates an overflow bit
$q$ for the foreign field equation above, when $q = 1$ there is a corresponding
subtraction that may introduce carries (or even borrows) between the limbs. This
is because $r = a + b - q \cdot f \mod 2^{264}$. Therefore, in the equations for
the limbs we will use a carry flag $c_i$ for limb $i$ to represent both carries
and borrows. The carry flags $c_i$ are in $\{-1, 0, 1\}$, where $c_i = -1$
represents a borrow and $c_i = 1$ represents a carry. Next we explain how this
works.

In order to perform this operation in parts, we first take a look at the least
significant limb, which is the easiest part. This means we want to know how to
compute $r_0$. First, if the addition of the bits in $a_0$ and $b_0$ produce a
carry (or borrow) bit, then it should propagate to the second limb. That means
one has to subtract $2^{88}$ from $a_0 + b_0$, add $1$ to $a_1 + b_1$ and set
the low carry flag $c_0$ to 1 (otherwise it is zero). Thus, the equation for the
lowest bit is

$$a_0 + s \cdot b_0 = q \cdot f_0 + r_0 + c_0 \cdot 2^{88}$$

Or put in another way, this is equivalent to saying that
$a_0 + b_0 - q \cdot f_0 - r_0$ is a multiple of $2^{88}$ (or, the existence of
the carry coefficient $c_0$).

This kind of equation needs an additional check that the carry coefficient $c_0$
is a correct carry value (belonging to $\{-1,0,1\}$). We will use this idea for
the remaining limbs as well.

Looking at the second limb, we first need to observe that the addition of $a_1$
and $b_1$ can, not only produce a carry bit $c_1$, but they may need to take
into account the carry bit from the first limb; $c_0$. Similarly to the above,

$$a_1 + s \cdot b_1 = q \cdot f_1 + r_1 + c_1 \cdot 2^{88} - c_0$$

Note that in this case, the carry coefficient from the least significant limb is
not multiplied by $2^{88}$, but instead is used as is, since it occupies the
least significant position of the second limb. Here, the second carry bit $c_1$
is the one being followed by $88$ zeros. Again, we will have to check that $c_1$
is a bit.

Finally, for the third limb, we obtain a similar equation. But in this case, we
do not have to take into account $c_0$ anymore, since it was already considered
within $c_1$. Here, the most significant carry bit $c_2$ should always be a zero
so we can ignore it.

$$a_2 + s \cdot b_2 = q \cdot f_2 + r_2 - c_1$$

Graphically, this is what is happening:

```text
bits  0..............87|88...........175|176...........263

a  =  (-------a0-------|-------a1-------|-------a2-------)
+
s = 1 | -1
·
b  =  (-------b0-------|-------b1-------|-------b2-------)
                       >                >                >
=                     c_0              c_1              c_2
q  =  -1 | 0 | 1
·
f  =  (-------f0-------|-------f1-------|-------f2-------)
+
r  =  (-------r0-------|-------r1-------|-------r2-------)
```

Our witness computation is currently using the `BigUint` library, which takes
care of all of the intermediate carry limbs itself so we do not have to address
all casuistries ourselves (such as propagating the low carry flag to the high
limb in case the middle limb is all zeros).

### Upper bound check for foreign field membership

Last but not least, we should perform some range checks to make sure that the
result $r$ is contained in $\mathbb{F}_f$. This is important because there could
be other values of the result which still fit in $<2^{264}$ but are larger than
$f$, and we must make sure that the final result is the minimum one (that we
will be referring to as $r_{min}$ in the following).

Ideally, we would like to reuse some gates that we already have. In particular,
we can perform range checks for $0\leq X <2^{3\ell}=2^{3\cdot 88}$. But we want
to check that $0 \leq r_{min} < f$, which is a smaller range. The way we can
tweak the existing range check gate to behave as we want, is as follows.

First, the above inequality is equivalent to $-f \leq r_{min} - f < 0$. Add
$2^{264}$ on both sides to obtain
$2^{264} - f \leq r_{min} - f + 2^{264} < 2^{264}$. Thus, we can perform the
standard $r_{min} \in [0,2^{264})$ check together with the
$r_{min} - f + 2^{264} \in [0,2^{264})$, which together will imply
$r_{min} \in [0,f)$ as intended. All there is left to check is that a given
upperbound term is correctly obtained; calling it $u$, we want to enforce
$u := r_{min} + 2^{264} - f$.

The following computation is very similar to a foreign field addition
($r_{min} + 2^{264} = u \mod f$), but simpler. The field overflow bit will
always be $1$, the main operation sign is positive $1$ (we are doing addition,
not subtraction), and the right input $2^{264}$, call it $g$, is represented by
the limbs $(0, 0, 2^{88})$. There could be intermediate limb carry bits $k_0$
and $k_1$ as in the general case FF addition protocol. Observe that, because the
sum is meant to be $<2^{264}$, the carry bit for the most significant limb
should always be zero $k_2 = 0$, so this condition is enforced implicitly by
omitting $k_2$ from the equations. Happily, we can apply the addition gate again
to perform the addition limb-wise, by selecting the following parameters:

$$
\begin{aligned}
a_0 &=& r_{min_{0}} \\ a_1 &=& r_{min_{1}} \\ a_2 &=& r_{min_{2}}  \\
b_0 &=& 0 \\ b_1 &=& 0 \\ b_2 &=& 2^{88}  \\
s &=& 1 \\
q &=& 1
\end{aligned}
$$

Calling $u$ the upper bound term, the equation
$r_{min} + 2^{264} - f $ can be expressed as $r_{min} + 2^{264} = 1 \cdot f + u$.
Finally, we perform a range check on the sum $u$, and we would know that
$r_{min} < f$.

```text
bits  0..............87|88...........175|176...........263

r  =  (-------r0-------|-------r1-------|-------r2-------)
+
g  =  (-------g0-------|-------g1-------|-------g2-------)
                       >                >
=                     k_0              k_1
f
+
u  =  (-------u0-------|-------u1-------|-------u2-------)
```

Following the steps above, and representing this equation in limb form, we have:

$$
\begin{aligned}
u_0 &= r_0 + 0 - f_0 - k_0 \cdot 2^{88} \\
u_1 &= r_1 + 0 - f_1 - k_1 \cdot 2^{88} + k_0 \\
u_2 &= r_2 + 2^{88} - f_2 + k_1 \\
\end{aligned}
$$

But now we also have to check that $0\leq r$. But this is implicitly covered by
$r$ being a field element of at most 264 bits (range check).

When we have a chain of additions $a_i + b_i = r_i$ with $a_i = {r_{i-1}}$, we
could apply the field membership check naively to every intermediate $r_i$,
however it is sufficient to apply it only once at the end of the computations
for $r_{n}$, and keep intermediate $r_i \in [0,2^{264})$, in a "raw" form.
Generally speaking, treating intermediate values lazily helps to save a lot of
computation in many different FF addition and multiplication scenarios.

### Subtractions

Mathematically speaking, a subtraction within a field is no more than an
addition over that field. Negative elements are not different from "positive"
elements in finite fields (or in any modular arithmetic). Our witness
computation code computes negative sums by adding the modulus to the result. To
give a general example, the element $-e$ within a field $\mathbb{F}_m$ of order
$m$ and $e < m$ is nothing but $m - e$. Nonetheless, for arbitrarily sized
elements (not just those smaller than the modulus), the actual field element
could be any $c \cdot m - e$, for any multiple $c \cdot m$ of the modulus. Thus,
representing negative elements directly as "absolute" field elements may incur
in additional computations involving multiplications and thus would result in a
less efficient mechanism.

Instead, our gate encodes subtractions and additions directly within the sign
term that is multiplying the right input. This way, there is no need to check
that the negated value is performed correctly (which would require an additional
row for a potential `FFNeg` gate).

### Optimization

So far, one can recompute the result as follows:

```text
bits  0..............87|88...........175|176...........263
r  =  (-------r0-------|-------r1-------|-------r2-------)
=
a  =  (-------a0-------|-------a1-------|-------a2-------)
+
s = 1 | -1
·
b  =  (-------b0-------|-------b1-------|-------b2-------)
-
q  =  -1 | 0 | 1
·
f  =  (-------f0-------|-------f1-------|-------f2-------)
                       >                >                >
                      c_0              c_1               0
```

Inspired by the halving approach in foreign field multiplication, an optimized
version of the above gate results in a reduction by 2 in the number of
constraints and by 1 in the number of witness cells needed. The main idea is to
condense the claims about the low and middle limbs in one single larger limb of
176 bits, which fit in our native field. This way, we can get rid of the low
carry flag, its corresponding carry check, and the three result checks become
just two.

```text
bits  0..............87|88...........175|176...........263
r  =  (-------r0------- -------r1-------|-------r2-------)
=
a  =  (-------a0------- -------a1-------|-------a2-------)
+
s = 1 | -1
·
b  =  (-------b0------- -------b1-------|-------b2-------)
-
q  =  -1 | 0 | 1
·
f  =  (-------f0------- -------f1-------|-------f2-------)
                                        >                >
                                        c                0
```

These are the new equations:

$$
\begin{aligned}
r_{bot} &= (a_0 + 2^{88} \cdot a_1) + s \cdot (b_0 + 2^{88} \cdot b_1) - q \cdot (f_0 + 2^{88} \cdot f_1) - c \cdot 2^{176} \\
r_{top} &= a_2 + s \cdot b_2 - q \cdot f_2 + c
\end{aligned}
$$

with $r_{top} = r_2$ and $c = c_1$.

## Gadget

The full foreign field addition/subtraction gadget will be composed of:

- $1$ public input row containing the value $1$;
- $n$ rows with `ForeignFieldAdd` gate type:
  - for the actual $n$ chained additions or subtractions;
- $1$ `ForeignFieldAdd` row for the bound addition;
- $1$ `Zero` row for the final bound addition.
- $1$ `RangeCheck` gadget for the first left input of the chain $a_1 := a$;
- Then, $n$ of the following set of rows:
  - $1$ `RangeCheck` gadget for the $i$-th right input $b_i$;
  - $1$ `RangeCheck` gadget for the $i$-th result which will correspond to the
    $(i+1)$-th left input of the chain $r_i = a_{i+1}$.
- $1$ final `RangeCheck` gadget for the bound check $u$.

A total of 20 rows with 15 columns in Kimchi for 1 addition. All ranges below
are inclusive.

| Row(s)           | Gate type(s)        | Witness |
| ---------------- | ------------------- | ------- |
| 0                | `PublicInput`       | $1$     |
| 1..n             | `ForeignFieldAdd`   | +/-     |
| n+1              | `ForeignFieldAdd`   | bound   |
| n+2              | `Zero`              | bound   |
| n+3..n+6         | `multi-range-check` | left    |
| n+7+8i..n+10+8i  | `multi-range-check` | right   |
| n+11+8i..n+14+8i | `multi-range-check` | $r$     |
| 9n+7..9n+10      | `multi-range-check` | $u$     |

This mechanism can chain foreign field additions together. Initially, there are
$n$ foreign field addition gates, followed by a foreign field addition gate for
the bound addition (whose current row corresponds to the next row of the last
foreign field addition gate), and an auxiliary `Zero` row that holds the upper
bound. At the end, an initial left input range check is performed, which is
followed by a $n$ pairs of range check gates for the right input and
intermediate result (which become the left input for the next iteration). After
the chained inputs checks, a final range check on the bound takes place.

For example, chaining the following set of 3 instructions would result in a full
gadget with 37 rows:

$$add(add(add(a,b),c),d)$$

| Row(s) | Gate type(s)        | Witness       |
| ------ | ------------------- | ------------- |
| 0      | `PublicInput`       | $1$           |
| 1      | `ForeignFieldAdd`   | $a+b$         |
| 2      | `ForeignFieldAdd`   | $(a+b)+c$     |
| 3      | `ForeignFieldAdd`   | $((a+b)+c)+d$ |
| 4      | `ForeignFieldAdd`   | bound         |
| 5      | `Zero`              | bound         |
| 6..9   | `multi-range-check` | $a$           |
| 10..13 | `multi-range-check` | $b$           |
| 14..17 | `multi-range-check` | $a+b$         |
| 18..21 | `multi-range-check` | $c$           |
| 22..25 | `multi-range-check` | $a+b+c$       |
| 26..29 | `multi-range-check` | $d$           |
| 30..33 | `multi-range-check` | $a+b+c+d$     |
| 34..37 | `multi-range-check` | bound         |

Nonetheless, such an exhaustive set of checks are not necessary for completeness
nor soundness. In particular, only the very final range check for the bound is
required. Thus, a shorter gadget that is equally valid and takes $(8\cdot n+4)$
fewer rows could be possible if we can assume that the inputs of each addition
are correct foreign field elements. It would follow the next layout (with
inclusive ranges):

| Row(s)   | Gate type(s)                                          | Witness |
| -------- | ----------------------------------------------------- | ------- |
| 0        | public input row for soundness of bound overflow flag | $1$     |
| 1..n     | `ForeignFieldAdd`                                     |         |
| n+1      | `ForeignFieldAdd`                                     |         |
| n+2      | `Zero`                                                |         |
| n+3..n+6 | `multi-range-check` for `bound`                       | $u$     |

Otherwise, we would need range checks for each new input of the chain, but none
for intermediate results; implying $4\cdot n$ fewer rows.

| Row(s)          | Gate type(s)                                          | Witness   |
| --------------- | ----------------------------------------------------- | --------- |
| 0               | public input row for soundness of bound overflow flag | $1$       |
| 1..n            | `ForeignFieldAdd`                                     | $a_i+b_i$ |
| n+1             | `ForeignFieldAdd`                                     |           |
| n+2             | `Zero`                                                |           |
| n+3..n+6        | `multi-range-check` for first left input              | $a_1$     |
| n+7+4i..n+10+4i | `multi-range-check` for $i$-th right input            | $b_i$     |
| 5n+7..5n+10     | `multi-range-check` for bound                         | $u$       |

For more details see the Bound Addition section in
[Foreign Field Multiplication](../kimchi/foreign_field_mul.md) or the original
[Foreign Field Multiplication RFC](https://github.com/o1-labs/rfcs/blob/main/0006-ffmul-revised.md).

### Layout

For the full mode of tests of this gate, we need to perform 4 range checks to
assert that the limbs of $a, b, r, u$ have a correct size, meaning they fit in
$2^{88}$ (and thus, range-checking $a, b, r, u$ for $2^{264}$). Because each of
these elements is split into 3 limbs, we will have to use 3 copy constraints
between the `RangeCheck` gates and the `ForeignFieldAdd` rows (per element).
That amounts to 12 copy constraints. Recalling that Kimchi only allows for the
first 7 columns of each row to host a copy constraint, we necessarily have to
use 2 rows for the actual addition gate. The layout of these two rows is the
following:

|            | Curr              | Next              | ... Final    |
| ---------- | ----------------- | ----------------- | ------------ |
| **Column** | `ForeignFieldAdd` | `ForeignFieldAdd` | `Zero`       |
| 0          | $a_0$ (copy)      | $r_0$ (copy)      | $u_0$ (copy) |
| 1          | $a_1$ (copy)      | $r_1$ (copy)      | $u_1$ (copy) |
| 2          | $a_2$ (copy)      | $r_2$ (copy)      | $u_2$ (copy) |
| 3          | $b_0$ (copy)      |                   |
| 4          | $b_1$ (copy)      |                   |
| 5          | $b_2$ (copy)      |                   |
| 6          | $q$               |
| 7          | $c$               |
| 8          |                   |
| 9          |                   |
| 10         |                   |
| 11         |                   |
| 12         |                   |
| 13         |                   |
| 14         |                   |

### Constraints

So far, we have pointed out the following sets of constraints:

#### Main addition

- $0 = a_0 + b_0 - r_0 - q \cdot f_0 - 2^{88} \cdot c_0$
- $0 = a_1 + b_1 - r_1 - q \cdot f_1 + c_0 - 2^{88} \cdot c_1 $
- $0 = a_2 + b_2 - r_2 - q \cdot f_2 + c_1$

#### Carry checks

- $0 = c_0 \cdot (c_0 + 1) \cdot (c_0 - 1)$
- $0 = c_1 \cdot (c_0 + 1) \cdot (c_1 - 1)$

#### Sign checks

TODO: decide if we really want to keep this check or leave it implicit as it is
a coefficient value

- $0 = (s + 1) \cdot (s - 1)$

#### Overflow checks

- $0 = q \cdot (q - s)$

## Optimizations

When we use this gate as part of a larger chained gadget, we should optimize the
number of range check rows to avoid redundant checks. In particular, if the
result of an addition becomes one input of another addition, there is no need to
check twice that the limbs of that term have the right length.

The sign is now part of the coefficients of the gate. This will allow us to
remove the sign check constraint and release one witness cell element. But more
importantly, it brings soundness to the gate as it is now possible to wire the
$1$ public input to the overflow witness of the final bound check of every
addition chain.
