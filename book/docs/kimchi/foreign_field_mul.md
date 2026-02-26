# Foreign Field Multiplication

This document is an original RFC explaining how we constrain foreign field
multiplication (i.e. non-native field multiplication) in the Kimchi proof
system. For a more recent RFC, see
[FFmul RFC](https://github.com/o1-labs/rfcs/blob/main/0006-ffmul-revised.md).

**Changelog**

| Author(s)                            | Date         | Details                                          |
| ------------------------------------ | ------------ | ------------------------------------------------ |
| Joseph Spadavecchia and Anais Querol | October 2022 | Design of foreign field multiplication in Kimchi |

## Overview

This gate constrains

$$
a \cdot b = c \mod f
$$

where $a, b, c \in \mathbb{F_f}$, a foreign field with modulus $f$, using the
native field $\mathbb{F_n}$ with prime modulus $n$.

## Approach

In foreign field multiplication the foreign field modulus $f$ could be bigger or
smaller than the native field modulus $n$. When the foreign field modulus is
bigger, then we need to emulate foreign field multiplication by splitting the
foreign field elements up into limbs that fit into the native field element
size. When the foreign modulus is smaller everything can be constrained either
in the native field or split up into limbs.

Since our projected use cases are when the foreign field modulus is bigger (more
on this below) we optimize our design around this scenario. For this case, not
only must we split foreign field elements up into limbs that fit within the
native field, but we must also operate in a space bigger than the foreign field.
This is because we check the multiplication of two foreign field elements by
constraining its quotient and remainder. That is, renaming $c$ to $r$, we must
constrain

$$
a \cdot b = q \cdot f + r,
$$

where the maximum size of $q$ and $r$ is $f - 1$ and so we have

$$
\begin{aligned}
a \cdot b &\le \underbrace{(f - 1)}_q \cdot f + \underbrace{(f - 1)}_r \\
&\le f^2 - 1.
\end{aligned}
$$

Thus, the maximum size of the multiplication is quadratic in the size of foreign
field.

**Naïve approach**

Naïvely, this implies that we have elements of size $f^2 - 1$ that must split
them up into limbs of size at most $n - 1$. For example, if the foreign field
modulus is $256$ and the native field modulus is $255$ bits, then we'd need
$\log_2((2^{256})^2 - 1) \approx 512$ bits and, thus, require
$512/255 \approx 3$ native limbs. However, each limb cannot consume all $255$
bits of the native field element because we need space to perform arithmetic on
the limbs themselves while constraining the foreign field multiplication.
Therefore, we need to choose a limb size that leaves space for performing these
computations.

Later in this document (see the section entitled "Choosing the limb
configuration") we determine the optimal number of limbs that reduces the number
of rows and gates required to constrain foreign field multiplication. This
results in $\ell = 88$ bits as our optimal limb size. In the section about
intermediate products we place some upperbounds on the number of bits required
when constraining foreign field multiplication with limbs of size $\ell$ thereby
proving that the computations can fit within the native field size.

Observe that by combining the naïve approach above with a limb size of $88$
bits, we would require $512/88 \approx 6$ limbs for representing foreign field
elements. Each limb is stored in a witness cell (a native field element).
However, since each limb is necessarily smaller than the native field element
size, it must be copied to the range-check gate to constrain its value. Since
Kimchi only supports 7 copyable witness cells per row, this means that only one
foreign field element can be stored per row. This means a single foreign field
multiplication would consume at least 4 rows (just for the operands, quotient
and remainder). This is not ideal because we want to limit the number of rows
for improved performance.

**Chinese remainder theorem**

Fortunately, we can do much better than this, however, by leveraging the chinese
remainder theorem (CRT for short) as we will now show. The idea is to reduce the
number of bits required by constraining our multiplication modulo two coprime
moduli: $2^t$ and $n$. By constraining the multiplication with both moduli the
CRT guarantees that the constraints hold with the bigger modulus $2^t \cdot n$.

The advantage of this approach is that constraining with the native modulus $n$
is very fast, allowing us to speed up our non-native computations. This
practically reduces the costs to constraining with limbs over $2^t$, where $t$
is something much smaller than $512$.

For this to work, we must select a value for $t$ that is big enough. That is, we
select $t$ such that $2^t \cdot n > f^2 - 1$. As described later on in this
document, by doing so we reduce the number of bits required for our use cases to
$264$. With $88$ bit limbs this means that each foreign field element only
consumes $3$ witness elements, and that means the foreign field multiplication
gate now only consumes $2$ rows. The section entitled "Choosing $t$" describes
this in more detail.

**Overall approach**

Bringing it all together, our approach is to verify that

$$
\begin{aligned}
a \cdot b = q \cdot f + r
\end{aligned}
$$

over $\mathbb{Z^+}$. In order to do this efficiently we use the CRT, which means
that the equation holds mod $M = 2^t \cdot n$. For the equation to hold over the
integers we must also check that each side of the equation is less than
$2^t \cdot n$.

The overall steps are therefore

1. Apply CRT to equation (1)
   - Check validity with binary modulus $\mod 2^t$
   - Check validity with native modulus $\mod n$
2. Check each side of equation (1) is less than $M$
   - $a \cdot b < 2^t \cdot n$
   - $q \cdot f + r < 2^t \cdot n$

This then implies that

$$
a \cdot b = c \mod f.
$$

where $c = r$. That is, $a$ multiplied with $b$ is equal to $c$ where
$a,b,c \in \mathbb{F_f}$. There is a lot more to each of these steps. That is
the subject of the rest of this document.

**Other strategies**

Within our overall approach, aside from the CRT, we also use a number of other
strategies to reduce the number and degree of constraints.

- Avoiding borrows and carries
- Intermediate product elimination
- Combining multiplications

The rest of this document describes each part in detail.

## Parameter selection

This section describes important parameters that we require and how they are
computed.

- _Native field modulus_ $n$
- _Foreign field modulus_ $f$
- _Binary modulus_ $2^t$
- _CRT modulus_ $2^t \cdot n$
- _Limb size_ in bits $\ell$

#### Choosing $t$

Under the hood, we constrain $a \cdot b = q \cdot f + r \mod 2^t \cdot n$. Since
this is a multiplication in the foreign field $f$, the maximum size of $q$ and
$r$ are $f - 1$, so this means

$$
\begin{aligned}
a \cdot b &\le (f - 1) \cdot f + (f - 1) \\
&\le f^2 - 1.
\end{aligned}
$$

Therefore, we need the modulus $2^t \cdot n$ such that

$$
2^t \cdot n > f^2 - 1,
$$

which is the same as saying, given $f$ and $n$, we must select $t$ such that

$$
\begin{aligned}
2^t \cdot n &\ge f^2 \\
t &\ge 2\log_2(f) - \log_2(n).
\end{aligned}
$$

Thus, we have an lower bound on $t$.

Instead of dynamically selecting $t$ for every $n$ and $f$ combination, we fix a
$t$ that will work for the different selections of $n$ and $f$ relevant to our
use cases.

To guide us, from above we know that

$$
t_{min} = 2\log_2(f) - \log_2(n)
$$

and we know the field moduli for our immediate use cases.

```
vesta     = 2^254 + 45560315531506369815346746415080538113 (255 bits)
pallas    = 2^254 + 45560315531419706090280762371685220353 (255 bits)
secp256k1 = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 (256 bits)
```

So we can create a table

| $n$      | $f$         | $t_{min}$ |
| -------- | ----------- | --------- |
| `vesta`  | `secp256k1` | 258       |
| `pallas` | `secp256k1` | 258       |
| `vesta`  | `pallas`    | 255       |
| `pallas` | `vesta`     | 255       |

and know that to cover our use cases we need $t \ge 258$.

Next, given our native modulus $n$ and $t$, we can compute the _maximum foreign
field modulus supported_. Actually, we compute the maximum supported bit length
of the foreign field modulus $f=2^m$.

$$
\begin{aligned}
2^t \cdot n &\ge f^2 \\
&\ge (2^m)^2 = 2^{2m} \\
t + \log_2(n) &> \log_2(2^{2m}) = 2m
\end{aligned}
$$

So we get

$$
m_{max} = \frac{t + \log_2(n)}{2}.
$$

With $t=258, n=255$ we have

$$
\begin{aligned}
m_{max} &= \frac{258 + 255}{2} = 256.5,
\end{aligned}
$$

which is not enough space to handle anything larger than 256 bit moduli.
Instead, we will use $t=264$, giving $m_{max} = 259$ bits.

The above formula is useful for checking the maximum number of bits supported of
the foreign field modulus, but it is not useful for computing the maximum
foreign field modulus itself (because $2^{m_{max}}$ is too coarse). For these
checks, we can compute our maximum foreign field modulus more precisely with

$$
max_{mod} = \lfloor \sqrt{2^t \cdot n} \rfloor.
$$

The max prime foreign field modulus satisfying the above inequality for both
Pallas and Vesta is
`926336713898529563388567880069503262826888842373627227613104999999999999999607`.

#### Choosing the limb configuration

Choosing the right limb size and the right number of limbs is a careful balance
between the number of constraints (i.e. the polynomial degree) and the witness
length (i.e. the number of rows). Because one limiting factor that we have in
Kimchi is the 12-bit maximum for range check lookups, we could be tempted to
introduce 12-bit limbs. However, this would mean having many more limbs, which
would consume more witness elements and require significantly more rows. It
would also increase the polynomial degree by increasing the number of
constraints required for the _intermediate products_ (more on this later).

We need to find a balance between the number of limbs and the size of the limbs.
The limb configuration is dependent on the value of $t$ and our maximum foreign
modulus (as described in the previous section). The larger the maximum foreign
modulus, the more witness rows we will require to constrain the computation. In
particular, each limb needs to be constrained by the range check gate and, thus,
must be in a copyable (i.e. permuteable) witness cell. We have at most 7
copyable cells per row and gates can operate on at most 2 rows, meaning that we
have an upperbound of at most 14 limbs per gate (or 7 limbs per row).

As stated above, we want the foreign field modulus to fit in as few rows as
possible and we need to constrain operands $a, b$, the quotient $q$ and
remainder $r$. Each of these will require cells for each limb. Thus, the number
of cells required for these is

$$
cells = 4 \cdot limbs
$$

It is highly advantageous for performance to constrain foreign field
multiplication with the minimal number of gates. This not only helps limit the
number of rows, but also to keep the gate selector polynomial small. Because of
all of this, we aim to constrain foreign field multiplication with a single gate
(spanning at most $2$ rows). As mentioned above, we have a maximum of 14
permuteable cells per gate, so we can compute the maximum number of limbs that
fit within a single gate like this.

$$
\begin{aligned}
limbs_{max} &= \lfloor cells/4  \rfloor \\
      &= \lfloor 14/4 \rfloor \\
      &= 3 \\
\end{aligned}
$$

Thus, the maximum number of limbs possible in a single gate configuration is 3.

Using $limbs_{max}=3$ and $t=264$ that covers our use cases (see the previous
section), we are finally able to derive our limbs size

$$
\begin{aligned}
\ell &= \frac{t}{limbs_{max}} \\
&= 264/3 \\
&= 88
\end{aligned}
$$

Therefore, our limb configuration is:

- Limb size $\ell = 88$ bits
- Number of limbs is $3$

## Avoiding borrows

When we constrain $a \cdot b - q \cdot f = r \mod 2^t$ we want to be as
efficient as possible.

Observe that the expansion of $a \cdot b - q \cdot f$ into limbs would also have
subtractions between limbs, requiring our constraints to account for borrowing.
Dealing with this would create undesired complexity and increase the degree of
our constraints.

In order to avoid the possibility of subtractions we instead use
$a \cdot b + q \cdot f'$ where

$$
\begin{aligned}
f' &= -f \mod 2^t \\
   &= 2^t - f
\end{aligned}
$$

The negated modulus $f'$ becomes part of our gate coefficients and is not
constrained because it is publicly auditable.

Using the substitution of the negated modulus, we now must constrain
$a \cdot b + q \cdot f' = r \mod 2^t$.

> Observe that $f' < 2^t$ since $f < 2^t$ and that $f' > f$ when
> $f < 2^{t - 1}$.

## Intermediate products

This section explains how we expand our constraints into limbs and then
eliminate a number of extra terms.

We must constrain $a \cdot b + q \cdot f' = r \mod 2^t$ on the limbs, rather
than as a whole. As described above, each foreign field element $x$ is split
into three 88-bit limbs: $x_0, x_1, x_2$, where $x_0$ contains the least
significant bits and $x_2$ contains the most significant bits and so on.

Expanding the right-hand side into limbs we have

$$
\begin{aligned}
&(a_0 + a_1 \cdot 2^{\ell} + a_2 \cdot 2^{2\ell}) \cdot (b_0 + b_1 \cdot 2^{\ell} + b_2 \cdot 2^{2\ell}) +  (q_0 + q_1 \cdot 2^{\ell} + q_2 \cdot 2^{2\ell}) \cdot (f'_0 + f'_1 \cdot 2^{\ell} + f'_2 \cdot 2^{2\ell}) \\
&=\\
&~~~~~ a_0 \cdot b_0 + a_0 \cdot b_1 \cdot 2^{\ell} + a_0 \cdot b_2 \cdot 2^{2\ell} \\
&~~~~ + a_1 \cdot b_0 \cdot 2^{\ell} + a_1 \cdot b_1 \cdot 2^{2\ell} + a_1 \cdot b_2 \cdot 2^{3\ell} \\
&~~~~ + a_2 \cdot b_0 \cdot 2^{2\ell} + a_2 \cdot b_1 \cdot 2^{3\ell} + a_2 \cdot b_2 \cdot 2^{4\ell} \\
&+ \\
&~~~~~ q_0 \cdot f'_0 + q_0 \cdot f'_1 \cdot 2^{\ell} + q_0 \cdot f'_2 \cdot 2^{2\ell} \\
&~~~~ + q_1 \cdot f'_0 \cdot 2^{\ell} + q_1 \cdot f'_1 \cdot 2^{2\ell} + q_1 \cdot f'_2 \cdot 2^{3\ell} \\
&~~~~ + q_2 \cdot f'_0 \cdot 2^{2\ell} + q_2 \cdot f'_1 \cdot 2^{3\ell} + q_2 \cdot f'_2 \cdot 2^{4\ell} \\
&= \\
&a_0 \cdot b_0 + q_0 \cdot f'_0 \\
&+ 2^{\ell} \cdot (a_0 \cdot b_1 + a_1 \cdot b_0 + q_0 \cdot f'_1 + q_1 \cdot f'_0) \\
&+ 2^{2\ell} \cdot (a_0 \cdot b_2 + a_2 \cdot b_0 + q_0 \cdot f'_2 + q_2 \cdot f'_0 + a_1 \cdot b_1 + q_1 \cdot f'_1) \\
&+ 2^{3\ell} \cdot (a_1 \cdot b_2 + a_2 \cdot b_1 + q_1 \cdot f'_2 + q_2 \cdot f'_1) \\
&+ 2^{4\ell} \cdot (a_2 \cdot b_2 + q_2 \cdot f'_2) \\
\end{aligned}
$$

Since $t = 3\ell$, the terms scaled by $2^{3\ell}$ and $2^{4\ell}$ are a
multiple of the binary modulus and, thus, congruent to zero $\mod 2^t$. They can
be eliminated and we don't need to compute them. So we are left with 3
_intermediate products_ that we call $p_0, p_1, p_2$:

| Term  | Scale       | Product                                                  |
| ----- | ----------- | -------------------------------------------------------- |
| $p_0$ | $1$         | $a_0b_0 + q_0f'_0$                                       |
| $p_1$ | $2^{\ell}$  | $a_0b_1 + a_1b_0 + q_0f'_1 + q_1f'_0$                    |
| $p_2$ | $2^{2\ell}$ | $a_0b_2 + a_2b_0 + q_0f'_2 + q_2f'_0 + a_1b_1 + q_1f'_1$ |

So far, we have introduced these checked computations to our constraints

> 1. Computation of $p_0, p_1, p_2$

## Constraining $\mod 2^t$

Let's call $p := ab + qf' \mod 2^t$. Remember that our goal is to constrain that
$p - r = 0 \mod 2^t$ (recall that any more significant bits than the 264th are
ignored in $\mod 2^t$). Decomposing that claim into limbs, that means

$$
\begin{aligned}
2^{2\ell}(p_2 - r_2) + 2^{\ell}(p_1 - r_1) + p_0 - r_0 = 0 \mod 2^t.
\end{aligned}
$$

We face two challenges

- Since $p_0, p_1, p_2$ are at least $2^{\ell}$ bits each, the right side of the
  equation above does not fit in $\mathbb{F}_n$
- The subtraction of the remainder's limbs $r_0$ and $r_1$ could require
  borrowing

For the moment, let's not worry about the possibility of borrows and instead
focus on the first problem.

## Combining multiplications

The first problem is that our native field is too small to constrain
$2^{2\ell}(p_2 - r_2) + 2^{\ell}(p_1 - r_1) + p_0 - r_0 = 0 \mod 2^t$. We could
split this up by multiplying $a \cdot b$ and $q \cdot f'$ separately and create
constraints that carefully track borrows and carries between limbs. However, a
more efficient approach is combined the whole computation together and
accumulate all the carries and borrows in order to reduce their number.

The trick is to assume a space large enough to hold the computation, view the
outcome in binary and then split it up into chunks that fit in the native
modulus.

To this end, it helps to know how many bits these intermediate products require.
On the left side of the equation, $p_0$ is at most $2\ell + 1$ bits. We can
compute this by substituting the maximum possible binary values (all bits set
to 1) into $p_0 = a_0b_0 + q_0f'_0$ like this

$$
\begin{aligned}
\mathsf{maxbits}(p_0) &= \log_2(\underbrace{(2^{\ell} - 1)}_{a_{0}} \underbrace{(2^{\ell} - 1)}_{b_{0}} + \underbrace{(2^{\ell} - 1)}_{q_{0}} \underbrace{(2^{\ell} - 1)}_{f'_{0}}) \\
&= \log_2(2(2^{2\ell} - 2^{\ell + 1} + 1)) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2).
\end{aligned}
$$

So $p_0$ fits in $2\ell + 1$ bits. Similarly, $p_1$ needs at most $2\ell + 2$
bits and $p_2$ is at most $2\ell + 3$ bits.

| Term     | $p_0$       | $p_1$       | $p_2$       |
| -------- | ----------- | ----------- | ----------- |
| **Bits** | $2\ell + 1$ | $2\ell + 2$ | $2\ell + 3$ |

The diagram below shows the right hand side of the zero-sum equality from
equation (2). That is, the value $p - r$. Let's look at how the different bits
of $p_0, p_1, p_2, r_0, r_1$ and $r_2$ impact it.

```text
0             L             2L            3L            4L
|-------------|-------------|-------------|-------------|-------------|
                            :
|--------------p0-----------:-| 2L + 1
                            :
              |-------------:-p1------------| 2L + 2
                    p10➚    :        p11➚
                            |----------------p2-------------| 2L + 3
                            :
|-----r0------|             :
                            :
              |-----r1------|
                            :
                            |-----r2------|
\__________________________/ \______________________________/
             ≈ h0                           ≈ h1
```

Within our native field modulus we can fit up to $2\ell + \delta < \log_2(n)$
bits, for small values of $\delta$ (but sufficient for our case). Thus, we can
only constrain approximately half of $p - r$ at a time. In the diagram above the
vertical line at 2L bisects $p - r$ into two $\approx2\ell$ bit values: $h_0$
and $h_1$ (the exact definition of these values follow). Our goal is to
constrain $h_0$ and $h_1$.

## Computing the zero-sum halves: $h_0$ and $h_1$

Now we can derive how to compute $h_0$ and $h_1$ from $p$ and $r$.

The direct approach would be to bisect both $p_0$ and $p_1$ and then define
$h_0$ as just the sum of the $2\ell$ lower bits of $p_0$ and $p_1$ minus $r_0$
and $r_1$. Similarly $h_1$ would be just the sum of upper bits of $p_0, p_1$ and
$p_2$ minus $r_2$. However, each bisection requires constraints for the
decomposition and range checks for the two halves. Thus, we would like to avoid
bisections as they are expensive.

Ideally, if our $p$'s lined up on the $2\ell$ boundary, we would not need to
bisect at all. However, we are unlucky and it seems like we must bisect both
$p_0$ and $p_1$. Fortunately, we can at least avoid bisecting $p_0$ by allowing
it to be summed into $h_0$ like this

$$
h_0 = p_0 + 2^{\ell}\cdot p_{10} - r_0 - 2^{\ell}\cdot r_1
$$

Note that $h_0$ is actually greater than $2\ell$ bits in length. This may not
only be because it contains $p_0$ whose length is $2\ell + 1$, but also because
adding $p_{10}$ may cause an overflow. The maximum length of $h_0$ is computed
by substituting in the maximum possible binary value of $2^{\ell} - 1$ for the
added terms and $0$ for the subtracted terms of the above equation.

$$
\begin{aligned}
\mathsf{maxbits}(h_0) &= \log_2(\underbrace{(2^{\ell} - 1)(2^{\ell} - 1) + (2^{\ell} - 1)(2^{\ell} - 1)}_{p_0} + 2^{\ell} \cdot \underbrace{(2^{\ell} - 1)}_{p_{10}}) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2 + 2^{2\ell} - 2^\ell) \\
&= \log_2( 3\cdot 2^{2\ell} - 5 \cdot 2^\ell +2 ) \\
\end{aligned}
$$

which is $2\ell + 2$ bits.

N.b. This computation assumes correct sizes values for $r_0$ and $r_1$, which we
assure by range checks on the limbs.

Next, we compute $h_1$ as

$$
h_1 = p_{11} + p_2 - r_2
$$

The maximum size of $h_1$ is computed as

$$
\begin{aligned}
\mathsf{maxbits}(h_1) &= \mathsf{maxbits}(p_{11} + p_2)
\end{aligned}
$$

In order to obtain the maximum value of $p_{11}$, we define
$p_{11} := \frac{p_1}{2^\ell}$. Since the maximum value of $p_1$ was
$2^{2\ell+2}-2^{\ell+3}+4$, then the maximum value of $p_{11}$ is
$2^{\ell+2}-8$. For $p_2$, the maximum value was
$6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6$, and thus:

$$
\begin{aligned}
\mathsf{maxbits}(h_1) &= log_2(\underbrace{2^{\ell+2}-8}_{p_{11}} + \underbrace{6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6}_{p_2}) \\
&= \log_2(6\cdot 2^{2\ell} - 8 \cdot 2^\ell - 2) \\
\end{aligned}
$$

which is $2\ell + 3$ bits.

| Term     | $h_0$       | $h_1$       |
| -------- | ----------- | ----------- |
| **Bits** | $2\ell + 2$ | $2\ell + 3$ |

Thus far we have the following constraints

> 2. Composition of $p_{10}$ and $p_{11}$ result in $p_1$
> 3. Range check $p_{11} \in [0, 2^{\ell + 2})$
> 4. Range check $p_{10} \in [0, 2^{\ell})$

For the next step we would like to constrain $h_0$ and $h_1$ to zero.
Unfortunately, we are not able to do this!

- Firstly, as defined $h_0$ may not be zero because we have not bisected it
  precisely at $2\ell$ bits, but have allowed it to contain the full $2\ell + 2$
  bits. Recall that these two additional bits are because $p_0$ is at most
  $2\ell + 1$ bits long, but also because adding $p_{10}$ increases it to
  $2\ell + 2$. These two additional bits are not part of the first $2\ell$ bits
  of $p - r$ and, thus, are not necessarily zero. That is, they are added from
  the second $2\ell$ bits (i.e. $h_1$).

- Secondly, whilst the highest $\ell + 3$ bits of $p - r$ would wrap to zero
  $\mod 2^t$, when placed into the smaller $2\ell + 3$ bit $h_1$ in the native
  field, this wrapping does not happen. Thus, $h_1$'s $\ell + 3$ highest bits
  may be nonzero.

We can deal with this non-zero issue by computing carry witness values.

## Computing carry witnesses values $v_0$ and $v_1$

Instead of constraining $h_0$ and $h_1$ to zero, there must be satisfying
witness $v_0$ and $v_1$ such that the following constraints hold.

> 5. There exists $v_0$ such that $h_0 = v_0 \cdot 2^{2\ell}$
> 6. There exists $v_1$ such that $h_1 = v_1 \cdot 2^{\ell} - v_0$

Here $v_0$ is the last two bits of $h_0$'s $2\ell + 2$ bits, i.e., the result of
adding the highest bit of $p_0$ and any possible carry bit from the operation of
$h_0$. Similarly, $v_1$ corresponds to the highest $\ell + 3$ bits of $h_1$. It
looks like this

```text
0             L             2L            3L            4L
|-------------|-------------|-------------|-------------|-------------|
                            :
|--------------h0-----------:--| 2L + 2
                            : ↖v0
                            :-------------h1-------------| 2L + 3
                            :              \____________/
                            :                  v1➚
```

Remember we only need to prove the first $3\ell$ bits of $p - r$ are zero, since
everything is $\mod 2^t$ and $t = 3\ell$. It may not be clear how this approach
proves the $3\ell$ bits are indeed zero because within $h_0$ and $h_1$ there are
bits that are nonzero. The key observation is that these bits are too high for
$\mod 2^t$.

By making the argument with $v_0$ and $v_1$ we are proving that $h_0$ is
something where the $2\ell$ least significant bits are all zeros and that
$h_1 + v_0$ is something where the $\ell$ are also zeros. Any nonzero bits after
$3\ell$ do not matter, since everything is $\mod 2^t$.

All that remains is to range check $v_0$ and $v_1$

> 7. Range check $v_0 \in [0, 2^2)$
> 8. Range check $v_1 =\in [0, 2^{\ell + 3})$

## Subtractions

When unconstrained, computing
$u_0 = p_0 + 2^{\ell} \cdot p_{10} - (r_0 + 2^{\ell} \cdot r_1)$ could require
borrowing. Fortunately, we have the constraint that the $2\ell$ least
significant bits of $u_0$ are `0` (i.e. $u_0 = 2^{2\ell} \cdot v_0$), which
means borrowing cannot happen.

Borrowing is prevented because when the $2\ell$ least significant bits of the
result are `0` it is not possible for the minuend to be less than the
subtrahend. We can prove this by contradiction.

Let

- $x = p_0 + 2^{\ell} \cdot p_{10}$
- $y = r_0 + 2^{\ell} \cdot r_1$
- the $2\ell$ least significant bits of $x - y$ be `0`

Suppose that borrowing occurs, that is, that $x < y$. Recall that the length of
$x$ is at most $2\ell + 2$ bits. Therefore, since $x < y$ the top two bits of
$x$ must be zero and so we have

$$
x - y = x_{2\ell} - y,
$$

where $x_{2\ell}$ denotes the $2\ell$ least significant bits of $x$.

Recall also that the length of $y$ is $2\ell$ bits. We know this because limbs
of the result are each constrained to be in $[0, 2^{\ell})$. So the result of
this subtraction is $2\ell$ bits. Since the $2\ell$ least significant bits of
the subtraction are `0` this means that

$$
\begin{aligned}
x - y  &  = 0 \\
x &= y,
\end{aligned}
$$

which is a contradiction with $x < y$.

## Costs

Range checks should be the dominant cost, let's see how many we have.

Range check (3) requires two range checks for
$p_{11} = p_{111} \cdot 2^\ell + p_{110}$

- a) $p_{110} \in [0, 2^\ell)$
- b) $p_{111} \in [0, 2^2)$

Range check (8) requires two range checks and a decomposition check that is
merged in (6).

- a) $v_{10} \in [0, 2^{\ell})$
- b) $v_{11} \in [0, 2^3)$

The range checks on $p_0, p_1$ and $p_2$ follow from the range checks on $a,b$
and $q$.

So we have 3.a, 3.b, 4, 7, 8.a, 8.b.

| Range check | Gate type(s)                                     | Witness                   | Rows |
| ----------- | ------------------------------------------------ | ------------------------- | ---- |
| 7           | $(v_0 - 3)(v_0 - 2)(v_0 - 1)v_0$                 | $v_0$                     | < 1  |
| 3.a         | $(p_{111} - 3)(p_{111} - 2)(p_{111} - 1)p_{111}$ | $p_{111}$                 | < 1  |
| 8.b         | degree-8 constraint or plookup                   | $v_{11}$                  | 1    |
| 3.b, 4, 8.a | `multi-range-check`                              | $p_{10}, p_{110}, v_{10}$ | 4    |

So we have 1 multi-range-check, 1 single-range-check and 2 low-degree range
checks. This consumes just over 5 rows.

## Use CRT to constrain $a \cdot b - q \cdot f - r \equiv 0 \mod n$

Until now we have constrained the equation $\mod 2^t$, but remember that our
application of the CRT means that we must also constrain the equation $\mod n$.
We are leveraging the fact that if the identity holds for all moduli in
$\mathcal{M} = \{n, 2^t\}$, then it holds for
$\mathtt{lcm} (\mathcal{M}) = 2^t \cdot n = M$.

Thus, we must check $a \cdot b - q \cdot f - r \equiv 0 \mod n$, which is over
$\mathbb{F}_n$.

This gives us equality $\mod 2^t \cdot n$ as long as the divisors are coprime.
That is, as long as $\mathsf{gcd}(2^t, n) = 1$. Since the native modulus $n$ is
prime, this is true.

Thus, to perform this check is simple. We compute

$$
\begin{aligned}
a_n &= a \mod n \\
b_n &= b \mod n \\
q_n &= q \mod n \\
r_n &= r \mod n \\
f_n &= f \mod n
\end{aligned}
$$

using our native field modulus with constraints like this

$$
\begin{aligned}
a_n &= 2^{2\ell} \cdot a_2 + 2^{\ell} \cdot a_1 + a_0 \\
b_n &= 2^{2\ell} \cdot b_2 + 2^{\ell} \cdot b_1 + b_0 \\
q_n &= 2^{2\ell} \cdot q_2 + 2^{\ell} \cdot q_1 + q_0 \\
r_n & = 2^{2\ell} \cdot r_2 + 2^{\ell} \cdot r_1 + r_0 \\
f_n &= 2^{2\ell} \cdot f_2 + 2^{\ell} \cdot f_1 + f_0 \\
\end{aligned}
$$

and then constrain

$$
a_n \cdot b_n - q_n \cdot f_n - r_n = 0 \mod n.
$$

Note that we do not use the negated foreign field modulus here.

This requires a single constraint of the form

> 9. $a_n \cdot b_n - q_n \cdot f_n = r_n$

with all of the terms expanded into the limbs according the above equations. The
values $a_n, b_n, q_n, f_n$ and $r_n$ do not need to be in the witness.

## Range check both sides of $a \cdot b = q \cdot f + r$

Until now we have constrained that equation $a \cdot b = q \cdot f + r$ holds
modulo $2^t$ and modulo $n$, so by the CRT it holds modulo $M = 2^t \cdot n$.
Remember that, as outlined in the "Overview" section, we must prove our equation
over the positive integers, rather than $\mod M$. By doing so, we assure that
our solution is not equal to some $q' \cdot M + r'$ where $q', r' \in F_{M}$, in
which case $q$ or $r$ would be invalid.

First, let's consider the right hand side $q \cdot f + r$. We have

$$
q \cdot f + r < 2^t \cdot n
$$

Recall that we have parameterized $2^t \cdot n \ge f^2$, so if we can bound $q$
and $r$ such that

$$
q \cdot f + r < f^2
$$

then we have achieved our goal. We know that $q$ must be less than $f$, so that
is our first check, leaving us with

$$
\begin{aligned}
(f - 1) \cdot f + r &< f^2 \\
r &< f^2 - (f - 1) \cdot f = f
\end{aligned}
$$

Therefore, to check $q \cdot f + r < 2^t \cdot n$, we need to check

- $q < f$
- $r < f$

This should come at no surprise, since that is how we parameterized
$2^t \cdot n$ earlier on. Note that by checking $q < f$ we assure correctness,
while checking $r < f$ assures our solution is unique (sometimes referred to as
canonical).

Next, we must perform the same checks for the left hand side (i.e.,
$a \cdot b < 2^t \cdot n$). Since $a$ and $b$ must be less than the foreign
field modulus $f$, this means checking

- $a < f$
- $b < f$

So we have

$$
\begin{aligned}
a \cdot b &\le (f - 1) \cdot (f - 1) = f^2 - 2f + 1 \\
\end{aligned}
$$

Since $2^t \cdot n \ge f^2$ we have

$$
\begin{aligned}
&f^2 - 2f + 1 < f^2 \le 2^t \cdot n \\
&\implies
a \cdot b < 2^t \cdot n
\end{aligned}
$$

### Bound checks

To perform the above range checks we use the _upper bound check_ method
described in the upper bound check section in
[Foreign Field Addition](./foreign_field_add#upper-bound-check-for-foreign-field-membership).

The upper bound check is as follows. We must constrain $0 \le q < f$ over the
positive integers, so

$$
\begin{aligned}
2^t \le q &+ 2^t < f + 2^t \\
2^t - f \le q &+ 2^t - f < 2^t \\
\end{aligned}
$$

Remember $f' = 2^t - f$ is our negated foreign field modulus. Thus, we have

$$
\begin{aligned}
f' \le q &+ f' < 2^t \\
\end{aligned}
$$

So to check $q < t$ we just need to compute $q' = q + f'$ and check
$f' \le q' < 2^t$

Observe that

$$
0 \le q \implies  f' \le q'
$$

and that

$$
q' < 2^t \implies q < f
$$

So we only need to check

- $0 \le q$
- $q' < 2^t$

The first check is always true since we are operating over the positive integers
and $q \in \mathbb{Z^+}$. Observe that the second check also constrains that
$q < 2^t$, since $f \le 2^{259} < 2^t$ and thus

$$
\begin{aligned}
q' &\le 2^t \\
q + f' &\le 2^t \\
q &\le 2^t - (2^t - f) = f\\
q &< 2^t
\end{aligned}
$$

Therefore, to constrain $q < f$ we only need constraints for

- $q' = q + f'$
- $q' < 2^t$

and we don't require an additional multi-range-check for $q < 2^t$.

### Cost of bound checks

This section analyzes the structure and costs of bounds checks for foreign field
addition and foreign field multiplication.

#### Addition

In our foreign field addition design the operands $a$ and $b$ do not need to be
less than $f$. The field overflow bit $\mathcal{o}$ for foreign field addition
is at most 1. That is, $a + b = \mathcal{o} \cdot f + r$, where $r$ is allowed
to be greater than $f$. Therefore,

$$
(f + a) + (f + b) = 1 \cdot f + (f + a + b)
$$

These can be chained along $k$ times as desired. The final result

$$
r = (\underbrace{f + \cdots + f}_{k} + a_1 + b_1 + \cdots a_k + b_k)
$$

Since the bit length of $r$ increases logarithmically with the number of
additions, in Kimchi we must only check that the final $r$ in the chain is less
than $f$ to constrain the entire chain.

> **Security note:** In order to defer the $r < f$ check to the end of any chain
> of additions, it is extremely important to consider the potential impact of
> wraparound in $\mathbb{F_n}$. That is, we need to consider whether the
> addition of a large chain of elements greater than the foreign field modulus
> could wrap around. If this could happen then the $r < f$ check could fail to
> detect an invalid witness. Below we will show that this is not possible in
> Kimchi.
>
> Recall that our foreign field elements are comprised of 3 limbs of 88-bits
> each that are each represented as native field elements in our proof system.
> In order to wrap around and circumvent the $r < f$ check, the highest limb
> would need to wrap around. This means that an attacker would need to perform
> about $k \approx n/2^{\ell}$ additions of elements greater than then foreign
> field modulus. Since Kimchi's native moduli (Pallas and Vesta) are 255-bits,
> the attacker would need to provide a witness for about $k \approx 2^{167}$
> additions. This length of witness is greater than Kimchi's maximum circuit
> (resp. witness) length. Thus, it is not possible for the attacker to generate
> a false proof by causing wraparound with a large chain of additions.

In summary, for foreign field addition in Kimchi it is sufficient to only bound
check the last result $r'$ in a chain of additions (and subtractions)

- Compute bound $r' = r + f'$ with addition gate (2 rows)
- Range check $r' < 2^t$ (4 rows)

#### Multiplication

In foreign field multiplication, the situation is unfortunately different, and
we must check that each of $a, b, q$ and $r$ are less than $f$. We cannot adopt
the strategy from foreign field addition where the operands are allowed to be
greater than $f$ because the bit length of $r$ would increases linearly with the
number of multiplications. That is,

$$
(a_1 + f) \cdot (a_2 + f) = 1 \cdot f + \underbrace{f^2 + (a_1 + a_2 - 1) \cdot f + a_1 \cdot a_2}_{r}
$$

and after a chain of $k$ multiplication we have

$$
r = f^k + \ldots + a_1 \cdots a_k
$$

where $r > f^k$ quickly overflows our CRT modulus $2^t \cdot n$. For example,
assuming our maximum foreign modulus of $f = 2^{259}$ and either of Kimchi's
native moduli (i.e. Pallas or Vesta), $f^k > 2^t \cdot n$ for $k > 2$. That is,
an overflow is possible for a chain of greater than 1 foreign field
multiplication. Thus, we must check $a, b, q$ and $r$ are less than $f$ for each
multiplication.

Fortunately, in many situations the input operands may already be checked either
as inputs or as outputs of previous operations, so they may not be required for
each multiplication operation.

Thus, the $q'$ and $r'$ checks (or equivalently $q$ and $r$) are our main focus
because they must be done for every multiplication.

- Compute bound $q' = q + f'$ with addition gate (2 rows)
- Compute bound $r' = r + f'$ with addition gate (2 rows)
- Range check $q' < 2^t$ (4 rows)
- Range check $r' < 2^t$ (4 rows)

This costs 12 rows per multiplication. In a subsequent section, we will reduce
it to 8 rows.

### 2-limb decomposition

Due to the limited number of permutable cells per gate, we do not have enough
cells for copy constraining $q'$ and $r'$ (or $q$ and $r$) to their respective
range check gadgets. To address this issue, we must decompose $q'$ into 2 limbs
instead of 3, like so

$$
q' = q'_{01} + 2^{2\ell} \cdot q'_2
$$

and

$$
q'_{01} = q'_0 + 2^{\ell} \cdot q'_1
$$

Thus, $q'$ is decomposed into two limbs $q'_{01}$ (at most $2\ell$ bits) and
$q'_2$ (at most $\ell$ bits).

Note that $q'$ must be range checked by a `multi-range-check` gadget. To do this
the `multi-range-check` gadget must

- Store a copy of the limbs $q'_0, q'_1$ and $q'_2$ in its witness
- Range check that they are $\ell$ bit each
- Constrain that $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$ (this is done with a
  special mode of the `multi-range-check` gadget)
- Have copy constraints for $q'_{01}$ and $q'_2$ as outputs of the
  `ForeignFieldMul` gate and inputs to the `multi-range-check` gadget

Note that since the foreign field multiplication gate computes $q'$ from $q$
which is already in the witness and $q'_{01}$ and $q'_2$ have copy constraints
to a `multi-range-check` gadget that fully constrains their decomposition from
$q'$, then the `ForeignFieldMul` gate does not need to store an additional copy
of $q'_0$ and $q'_1$.

### An optimization

Since the $q < f$ and $r < f$ checks must be done for each multiplication it
makes sense to integrate them into the foreign field multiplication gate. By
doing this we can save 4 rows per multiplication.

Doing this doesn't require adding a lot more witness data because the operands
for the bound computations $q' = q + f'$ and $r' = r + f'$ are already present
in the witness of the multiplication gate. We only need to store the bounds $q'$
and $r'$ in permutable witness cells so that they may be copied to
multi-range-check gates to check they are each less than $2^t$.

To constrain $x + f' = x'$, the equation we use is

$$
x + 2^t = \mathcal{o} \cdot f + x',
$$

where $x$ is the original value, $\mathcal{o}=1$ is the field overflow bit and
$x'$ is the remainder and our desired addition result (e.g. the bound).
Rearranging things we get

$$
x + 2^t - f = x',
$$

which is just

$$
x + f' = x',
$$

Recall from the section "Avoiding borrows" that $f'$ is often larger than $f$.
At first this seems like it could be a problem because in multiplication each
operation must be less than $f$. However, this is because the maximum size of
the multiplication was quadratic in the size of $f$ (we use the CRT, which
requires the bound that $a \cdot b < 2^t \cdot n$). However, for addition the
result is much smaller and we do not require the CRT nor the assumption that the
operands are smaller than $f$. Thus, we have plenty of space in $\ell$-bit limbs
to perform our addition.

So, the equation we need to constrain is

$$
x + f' = x'.
$$

We can expand the left hand side into the 2 limb format in order to obtain 2
intermediate sums

$$
\begin{aligned}
s_{01} = x_{01} + f_{01}' \\
s_2 = x_2 + f'_2 \\
\end{aligned}
$$

where $x_{01}$ and $f'_{01}$ are defined like this

$$
\begin{aligned}
x_{01} = x_0 + 2^{\ell} \cdot x_1 \\
f'_{01} = f'_0 + 2^{\ell} \cdot f'_1 \\
\end{aligned}
$$

and $x$ and $f'$ are defined like this

$$
\begin{aligned}
x = x_{01} + 2^{2\ell} \cdot x_2 \\
f' = f'_{01} + 2^{2\ell} \cdot f'_2 \\
\end{aligned}
$$

Going back to our intermediate sums, the maximum bit length of sum $s_{01}$ is
computed from the maximum bit lengths of $x_{01}$ and $f'_{01}$

$$
\underbrace{(2^{\ell} - 1) + 2^{\ell} \cdot (2^{\ell} - 1)}_{x_{01}} + \underbrace{(2^{\ell} - 1) + 2^{\ell} \cdot (2^{\ell} - 1)}_{f'_{01}} = 2^{2\ell+ 1} - 2,
$$

which means $s_{01}$ is at most $2\ell + 1$ bits long.

Similarly, since $x_2$ and $f'_2$ are less than $2^{\ell}$, the max value of
$s_2$ is

$$
(2^{\ell} - 1) + (2^{\ell} - 1) = 2^{\ell + 1} - 2,
$$

which means $s_2$ is at most $\ell + 1$ bits long.

Thus, we must constrain

$$
s_{01} + 2^{2\ell} \cdot s_2 - x'_{01} - 2^{2\ell} \cdot x'_2 = 0 \mod 2^t.
$$

The accumulation of this into parts looks like this.

```text
0             L             2L            3L=t          4L
|-------------|-------------|-------------|-------------|-------------|
                            :
|------------s01------------:-| 2L + 1
                            : ↖w01
                            |------s2-----:-| L + 1
                            :               ↖w2
                            :
|------------x'01-----------|
                            :
                            |------x'2----|
                            :
\____________________________/
             ≈ z01           \_____________/
                                   ≈ z2
```

The two parts are computed with

$$
\begin{aligned}
z_{01} &= s_{01} - x'_{01} \\
z_2 &= s_2 - x'_2.
\end{aligned}
$$

Therefore, there are two carry bits $w_{01}$ and $w_2$ such that

$$
\begin{aligned}
z_{01} &= 2^{2\ell} \cdot w_{01} \\
z_2 + w_{01} &= 2^{\ell} \cdot w_2
\end{aligned}
$$

In this scheme $x'_{01}, x'_2, w_{01}$ and $w_2$ are witness data, whereas
$s_{01}$ and $s_2$ are formed from a constrained computation of witness data
$x_{01}, x_2$ and constraint system public parameter $f'$. Note that due to
carrying, witness $x'_{01}$ and $x'_2$ can be different than the values $s_{01}$
and $s_2$ computed from the limbs.

Thus, each bound addition $x + f'$ requires the following witness data

- $x_{01}, x_2$
- $x'_{01}, x'_2$
- $w_{01}, w_2$

where $f'$ is baked into the gate coefficients. The following constraints are
needed

- $2^{2\ell} \cdot w_{01} = s_{01} - x'_{01}$
- $2^{\ell} \cdot w_2 = s_2 + w_{01} - x'_2$
- $x'_{01} \in [0, 2^{2\ell})$
- $x'_2 \in [0, 2^{\ell})$
- $w_{01} \in [0, 2)$
- $w_2 \in [0, 2)$

Due to the limited number of copyable witness cells per gate, we are currently
only performing this optimization for $q$.

The witness data is

- $q_0, q_1, q_2$
- $q'_{01}, q'_2$
- $q'_{carry01}, q'_{carry2}$

The checks are

1. $q_0 \in [0, 2^{\ell})$
2. $q_1 \in [0, 2^{\ell})$
3. $q'_0 = q_0 + f'_0$
4. $q'_1 = q_1 + f'_1$
5. $s_{01} = q'_0 + 2^{\ell} \cdot q'_1$
6. $q'_{01} \in [0, 2^{2\ell})$
7. $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$
8. $q'_{carry01} \in [0, 2)$
9. $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$
10. $q_2 \in [0, 2^{\ell})$
11. $s_2 = q_2 + f'_2$
12. $q'_{carry2} \in [0, 2)$
13. $2^{\ell} \cdot q'_{carry2} = s_2 + w_{01} - q'_2$

Checks (1) - (5) assure that $s_{01}$ is at most $2\ell + 1$ bits. Whereas
checks (10) - (11) assure that $s_2$ is at most $\ell + 1$ bits. Altogether they
are comprise a single `multi-range-check` of $q_0, q_1$ and $q_2$. However, as
noted above, we do not have enough copyable cells to output $q_1, q_2$ and $q_3$
to the `multi-range-check` gadget. Therefore, we adopt a strategy where the 2
limbs $q'_{01}$ and $q'_2$ are output to the `multi-range-check` gadget where
the decomposition of $q'_0$ and $q'_2$ into $q'_{01} = p_0 + 2^{\ell} \cdot p_1$
is constrained and then $q'_0, q'_1$ and $q'_2$ are range checked.

Although $q_1, q_2$ and $q_3$ are not range checked directly, this is safe
because, as shown in the "Bound checks" section, range-checking that
$q' \in [0, 2^t)$ also constrains that $q \in [0, 2^t)$. Therefore, the updated
checks are

1. $q_0 \in [0, 2^{\ell})$ `multi-range-check`
2. $q_1 \in [0, 2^{\ell})$ `multi-range-check`
3. $q'_0 = q_0 + f'_0$ `ForeignFieldMul`
4. $q'_1 = q_1 + f'_1$ `ForeignFieldMul`
5. $s_{01} = q'_0 + 2^{\ell} \cdot q'_1$ `ForeignFieldMul`
6. $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$ `multi-range-check`
7. $q'_{carry01} \in [0, 2)$ `ForeignFieldMul`
8. $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$ `ForeignFieldMul`
9. $q_2 \in [0, 2^{\ell})$ `multi-range-check`
10. $s_2 = q_2 + f'_2$ `ForeignFieldMul`
11. $q'_{carry2} \in [0, 2)$ `ForeignFieldMul`
12. $2^{\ell} \cdot q'_{carry2} = s_2 + q'_{carry01} - q'_2$ `ForeignFieldMul`

Note that we don't need to range-check $q'_{01}$ is at most $2\ell + 1$ bits
because it is already implicitly constrained by the `multi-range-check` gadget
constraining that $q'_0, q'_1$ and $q'_2$ are each at most $\ell$ bits and that
$q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$. Furthermore, since constraining the
decomposition is already part of the `multi-range-check` gadget, we do not need
to do it here also.

To simplify things further, we can combine some of these checks. Recall our
checked computations for the intermediate sums

$$
\begin{aligned}
s_{01} &= q_{01} + f'_{01} \\
s_2 &= q_2 + f'_2 \\
\end{aligned}
$$

where $q_{01} = q_0 + 2^{\ell} \cdot q_1$ and
$f'_{01} = f'_0 + 2^{\ell} \cdot f'_1$. These do not need to be separate
constraints, but are instead part of existing ones.

Checks (10) and (11) can be combined into a single constraint
$2^{\ell} \cdot q'_{carry2} = (q_2 + f'_2) + q'_{carry01} - q'_2$. Similarly,
checks (3) - (5) and (8) can be combined into
$2^{2\ell} \cdot q'_{carry01} = q_{01} + f'_{01} - q'_{01}$ with $q_{01}$ and
$f'_{01}$ further expanded. The reduced constraints are

1. $q_0 \in [0, 2^{\ell})$ `multi-range-check`
2. $q_1 \in [0, 2^{\ell})$ `multi-range-check`
3. $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$ `multi-range-check`
4. $q'_{carry01} \in [0, 2)$ `ForeignFieldMul`
5. $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$ `ForeignFieldMul`
6. $q_2 \in [0, 2^{\ell})$ `multi-range-check`
7. $q'_{carry2} \in [0, 2)$ `ForeignFieldMul`
8. $2^{\ell} \cdot q'_{carry2} = s_2 + w_{01} - q'_2$ `ForeignFieldMul`

Finally, there is one more optimization that we will exploit. This optimization
relies on the observation that for bound addition the second carry bit
$q'_{carry2}$ is always zero. This this may be obscure, so we will prove it by
contradiction. To simplify our work we rename some variables by letting
$x_0 = q_{01}$ and $x_1 = q_2$. Thus, $q'_{carry2}$ being non-zero corresponds
to a carry in $x_1 + f'_1$.

> **Proof:** To get a carry in the highest limbs $x_1 + f'_1$ during bound
> addition, we need
>
> $$
> 2^{\ell} < x_1 + \phi_0 + f'_1 \le 2^{\ell} - 1 + \phi_0 + f'_1
> $$
>
> where $2^{\ell} - 1$ is the maximum possible size of $x_1$ (before it
> overflows) and $\phi_0$ is the overflow bit from the addition of the least
> significant limbs $x_0$ and $f'_0$. This means
>
> $$
> 2^{\ell} - \phi_0 - f'_1 < x_1 < 2^{\ell}
> $$
>
> We cannot allow $x$ to overflow the foreign field, so we also have
>
> $$
> x_1 < (f - x_0)/2^{2\ell}
> $$
>
> Thus,
>
> $$
> 2^{\ell} - \phi_0  - f'_1 < (f - x_0)/2^{2\ell} = f/2^{2\ell} - x_0/2^{2\ell}
> $$
>
> Since $x_0/2^{2\ell} = \phi_0$ we have
>
> $$
> 2^{\ell} - \phi_0 - f'_1 < f/2^{2\ell} - \phi_0
> $$
>
> so
>
> $$
> 2^{\ell} - f'_1 < f/2^{2\ell}
> $$
>
> Notice that $f/2^{2\ell} = f_1$. Now we have
>
> $$
> 2^{\ell} - f'_1 < f_1 \\
> \Longleftrightarrow \\
> f'_1 > 2^{\ell} - f_1
> $$
>
> However, this is a contradiction with the definition of our negated foreign
> field modulus limb $f'_1 = 2^{\ell} - f_1$. $\blacksquare$

We have proven that $q'_{carry2}$ is always zero, so that allows use to simplify
our constraints. We now have

1. $q_0 \in [0, 2^{\ell})$ `multi-range-check`
2. $q_1 \in [0, 2^{\ell})$ `multi-range-check`
3. $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$ `multi-range-check`
4. $q'_{carry01} \in [0, 2)$ `ForeignFieldMul`
5. $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$ `ForeignFieldMul`
6. $q_2 \in [0, 2^{\ell})$ `multi-range-check`
7. $q'_2 = s_2 + w_{01}$ `ForeignFieldMul`

In other words, we have eliminated constraint (7) and removed $q'_{carry2}$ from
the witness.

Since we already needed to range-check $q$ or $q'$, the total number of new
constraints added is 4: 3 added to `ForeignFieldMul` and 1 added to
`multi-range-check` gadget for constraining the decomposition of $q'_{01}$.

This saves 2 rows per multiplication.

## Chaining multiplications

Due to the limited number of cells accessible to gates, we are not able to chain
multiplications into multiplications. We can chain foreign field additions into
foreign field multiplications, but currently do not support chaining
multiplications into additions (though there is a way to do it).

## Constraining the computation

Now we collect all of the checks that are required to constrain foreign field
multiplication

### 1. Range constrain $a$

If the $a$ operand has not been constrained to $[0, f)$ by any previous foreign
field operations, then we constrain it like this

- Compute bound $a' = a + f'$ with addition gate (2 rows) `ForeignFieldAdd`
- Range check $a' \in [0, 2^t)$ (4 rows) `multi-range-check`

### 2. Range constrain $b$

If the $b$ operand has not been constrained to $[0, f)$ by any previous foreign
field operations, then we constrain it like this

- Compute bound $b' = b + f'$ with addition gate (2 rows) `ForeignFieldAdd`
- Range check $b' \in [0, 2^t)$ (4 rows) `multi-range-check`

### 3. Range constrain $q$

The quotient $q$ is constrained to $[0, f)$ for each multiplication as part of
the multiplication gate

- Compute bound $q' = q + f'$ with `ForeignFieldMul` constraints
- Range check $q' \in [0, 2^t)$ (4 rows) `multi-range-check`
- Range check $q \ge 0$ `ForeignFieldMul` (implicit by storing `q` in witness)

### 4. Range constrain $r$

The remainder $r$ is constrained to $[0, f)$ for each multiplication using an
external addition gate.

- Compute bound $r' = r + f'$ with addition gate (2 rows) `ForeignFieldAdd`
- Range check $r' \in [0, 2^t)$ (4 rows) `multi-range-check`

### 5. Compute intermediate products

Compute and constrain the intermediate products $p_0, p_1$ and $p_2$ as:

- $p_0 = a_0 \cdot b_0 + q_0 \cdot f'_0$ `ForeignFieldMul`
- $p_1 = a_0 \cdot b_1 + a_1 \cdot b_0 + q_0 \cdot f'_1 + q_1 \cdot f'_0$
  `ForeignFieldMul`
- $p_2 = a_0 \cdot b_2 + a_2 \cdot b_0 + a_1 \cdot b_1 + q_0 \cdot f'_2 + q_2 \cdot f'_0 + q_1 \cdot f'_1$
  `ForeignFieldMul`

where each of them is about $2\ell$-length elements.

### 6. Native modulus checked computations

Compute and constrain the native modulus values, which are used to check the
constraints modulo $n$ in order to apply the CRT

- $a_n = 2^{2\ell} \cdot a_2 + 2^{\ell} \cdot a_1 + a_0 \mod n$
- $b_n = 2^{2\ell} \cdot b_2 + 2^{\ell} \cdot b_1 + b_0 \mod n$
- $q_n = 2^{2\ell} \cdot q_2 + 2^{\ell} \cdot q_1 + q_0 \mod n$
- $r_n = 2^{2\ell} \cdot r_2 + 2^{\ell} \cdot r_1 + r_0 \mod n$
- $f_n = 2^{2\ell} \cdot f_2 + 2^{\ell} \cdot f_1 + f_0 \mod n$

### 7. Decompose middle intermediate product

Check that $p_1 = 2^{\ell} \cdot p_{11} + p_{10}$:

- $p_1 = 2^\ell \cdot p_{11} + p_{10}$ `ForeignFieldMul`
- Range check $p_{10} \in [0, 2^\ell)$ `multi-range-check`
- Range check $p_{11} \in [0, 2^{\ell+2})$
  - $p_{11} = p_{111} \cdot 2^\ell + p_{110}$ `ForeignFieldMul`
  - Range check $p_{110} \in [0, 2^\ell)$ `multi-range-check`
  - Range check $p_{111} \in [0, 2^2)$ with a degree-4 constraint
    `ForeignFieldMul`

### 8. Zero sum for multiplication

Now we have to constrain the zero sum

$$
(p_0 - r_0) + 2^{88}(p_1 - r_1) + 2^{176}(p_2 - r_2) = 0 \mod 2^t
$$

We constrain the first and the second halves as

- $v_0 \cdot 2^{2\ell} = p_0 + 2^\ell \cdot p_{10} - r_0 - 2^\ell \cdot r_1$
  `ForeignFieldMul`
- $v_1 \cdot 2^{\ell} = (p_{111} \cdot 2^\ell + p_{110}) + p_2 - r_2 + v_0$
  `ForeignFieldMul`

And some more range checks

- Check that $v_0 \in [0, 2^2)$ with a degree-4 constraint `ForeignFieldMul`
- Check that $v_1 \in [0, 2^{\ell + 3})$
  - Check $v_1 = v_{11} \cdot 2^{88} + v_{10}$ `ForeignFieldMul`
  - Check $v_{11} \in [0, 2^3]$ `ForeignFieldMul`
  - Check $v_{10} < 2^\ell$ with range constraint `multi-range-check`

To check that $v_{11} \in [0, 2^3)$ (i.e. that $v_{11}$ is at most 3 bits long)
we first range-check $v_{11} \in [0, 2^{12})$ with a 12-bit plookup. This means
there can be no higher bits set beyond the 12-bits of $v_{11}$. Next, we scale
$v_{11}$ by $2^9$ in order to move the highest $12 - 3 = 9$ bits beyond the
$12$th bit. Finally, we perform a 12-bit plookup on the resulting value. That
is, we have

- Check $v_{11} \in [0, 2^{12})$ with a 12-bit plookup (to prevent any overflow)
- Check $\mathsf{scaled}_{v_{11}} = 2^9 \cdot v_{11}$
- Check $\mathsf{scaled}_{v_{11}}$ is a 12-bit value with a 12-bit plookup

Kimchi's plookup implementation is extremely flexible and supports optional
scaling of the lookup target value as part of the lookup operation. Thus, we do
not require two witness elements, two lookup columns, nor the
$\mathsf{scaled}_{v_{11}} = 2^9 \cdot v_{11}$ custom constraint. Instead we can
just store $v_{11}$ in the witness and define this column as a "joint lookup"
comprised of one 12-bit plookup on the original cell value and another 12-bit
plookup on the cell value scaled by $2^9$, thus, yielding a 3-bit check. This
eliminates one plookup column and reduces the total number of constraints.

### 9. Native modulus constraint

Using the checked native modulus computations we constrain that

$$
a_n \cdot b_n - q_n \cdot f_n - r_n = 0 \mod n.
$$

### 10. Compute intermediate sums

Compute and constrain the intermediate sums $s_{01}$ and $s_2$ as:

- $s_{01} = q_{01} + f'_{01}$
- $s_2 = q_2 + f_2'$
- $q_{01} = q_0 + 2^{\ell} \cdot q_1$
- $f'_{01} = f'_0 + 2^{\ell} \cdot f'_1$

### 11. Decompose the lower quotient bound

Check that $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$.

Done by (3) above with the `multi-range-check` on $q'$

- $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$
- Range check $q'_0 \in [0, 2^\ell)$
- Range check $q'_1 \in [0, 2^\ell)$

### 12. Zero sum for quotient bound addition

We constrain that

$$
s_{01} - q'_{01} + 2^{2\ell} \cdot (s_2 - q'_2) = 0 \mod 2^t
$$

by constraining the two halves

- $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$
- $2^{\ell} \cdot q'_{carry2} = s_2 + q'_{carry01} - q'_2$

We also need a couple of small range checks

- Check that $q'_{carry01}$ is boolean `ForeignFieldMul`
- Check that $q'_2$ is boolean `ForeignFieldMul`

# Layout

Based on the constraints above, we need the following 12 values copied from the
range check gates.

```
a0, a1, a2, b0, b1, b2, q0, q1, q2, r0, r1, r2
```

Since we need 12 copied values for the constraints, they must span 2 rows.

The $q < f$ bound limbs $q'_0, q'_1$ and $q'_2$ must be in copyable cells so
they can be range-checked. Similarly, the limbs of the operands $a$, $b$ and the
result $r$ must all be in copyable cells. This leaves only 2 remaining copyable
cells and, therefore, we cannot compute and output $r' = r + f'$. It must be
deferred to an external `ForeignFieldAdd` gate with the $r$ cells copied as an
argument.

NB: the $f$ and $f'$ values are publicly visible in the gate coefficients.

|            | Curr                      | Next             |
| ---------- | ------------------------- | ---------------- |
| **Column** | `ForeignFieldMul`         | `Zero`           |
| 0          | $a_0$ (copy)              | $r_0$ (copy)     |
| 1          | $a_1$ (copy)              | $r_1$ (copy)     |
| 2          | $a_2$ (copy)              | $r_2$ (copy)     |
| 3          | $b_0$ (copy)              | $q'_{01}$ (copy) |
| 4          | $b_1$ (copy)              | $q'_2$ (copy)    |
| 5          | $b_2$ (copy)              | $p_{10}$ (copy)  |
| 6          | $v_{10}$ (copy)           | $p_{110}$ (copy) |
| 7          | $v_{11}$ (scaled plookup) |                  |
| 8          | $v_0$                     |                  |
| 9          | $q_0$                     |                  |
| 10         | $q_1$                     |                  |
| 11         | $q_2$                     |                  |
| 12         | $q'_{carry01}$            |                  |
| 13         | $p_{111}$                 |                  |
| 14         |                           |                  |

# Checked computations

As described above foreign field multiplication has the following intermediate
computations

1. $p_0 = a_0b_0 + q_0f'_0$
2. $p_1 = a_0b_1 + a_1b_0 + q_0f'_1 + q_1f'_0$
3. $p_2 = a_0b_2 + a_2b_0 + a_1b_1 + q_0f'_2 + q_2f'_0 + q_1f'_1$.

For the $q$ bound addition we must also compute

1. $s_{01} = q_{01} + f'_{01}$
2. $s_2 = q_2 + f_2'$
3. $q_{01} = q_0 + 2^{\ell} \cdot q_1$
4. $f'_{01} = f'_0 + 2^{\ell} \cdot f'_1$

> Note the equivalence
>
> $$
> \begin{aligned}
> s_{01} &= q_{01} + f'_{01} \\
> &= q_0 + 2^{\ell} \cdot q_1 + f'_0 + 2^{\ell} \cdot f'_1 \\
> &= q_0 + f'_0 + 2^{\ell} \cdot (q'_1 + f'_1) \\
> &= q'_0 + 2^{\ell} \cdot q'_1
> \end{aligned}
> $$
>
> where $q'_0 = q_0 + f'_0$ and $q'_1 = q_1 + f'_1$ can be done with checked
> computations.

Next, for applying the CRT we compute

1. $a_n = 2^{2\ell} \cdot a_2 + 2^{\ell} \cdot a_1 + a_0 \mod n$
2. $b_n = 2^{2\ell} \cdot b_2 + 2^{\ell} \cdot b_1 + b_0 \mod n$
3. $q_n = 2^{2\ell} \cdot q_2 + 2^{\ell} \cdot q_1 + q_0 \mod n$
4. $r_n = 2^{2\ell} \cdot r_2 + 2^{\ell} \cdot r_1 + r_0 \mod n$
5. $f_n = 2^{2\ell} \cdot f_2 + 2^{\ell} \cdot f_1 + f_0 \mod n$

# Checks

In total we require the following checks

1. $p_{111} \in [0, 2^2)$
2. $v_{10} \in [0, 2^{\ell})$ `multi-range-check`
3. $p_{110} \in [0, 2^{\ell})$ `multi-range-check`
4. $p_{10} \in [0, 2^{\ell})$ `multi-range-check`
5. $p_{11} = 2^{\ell} \cdot p_{111} + p_{110}$
6. $p_1 = 2^{\ell} \cdot p_{11} + p_{10}$
7. $v_0 \in [0, 2^2)$
8. $2^{2\ell} \cdot v_0 = p_0 + 2^{\ell} \cdot p_{10} - r_0 - 2^{\ell} \cdot r_1$
9. $v_{11} \in [0, 2^{3})$
10. $v_1 = 2^{\ell} \cdot v_{11} + v_{10}$
11. $2^{\ell} \cdot v_1 = v_0 + p_{11} + p_2 - r_2$
12. $a_n \cdot b_n - q_n \cdot f_n = r_n$
13. $q'_0 \in [0, 2^{\ell})$ `multi-range-check`
14. $q'_1 \in [0, 2^{\ell})$ `multi-range-check`
15. $q'_2 \in [0, 2^{\ell})$ `multi-range-check`
16. $q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$ `multi-range-check`
17. $q'_{carry01} \in [0, 2)$
18. $2^{2\ell} \cdot q'_{carry01} = s_{01} - q'_{01}$
19. $q'_2 = s_2 + q'_{carry01}$

# Constraints

These checks can be condensed into the minimal number of constraints as follows.

First, we have the range-check corresponding to (1) as a degree-4 constraint

**C1:** $p_{111} \cdot (p_{111} - 1) \cdot (p_{111} - 2) \cdot (p_{111} - 3)$

Checks (2) - (4) are all handled by a single `multi-range-check` gadget.

**C2:** `multi-range-check` $v_{10}, p_{10}, p_{110}$

Next (5) and (6) can be combined into

**C3:** $2^{\ell} \cdot (2^{\ell} \cdot p_{111} + p_{110}) + p_{10} = p_1$

Now we have the range-check corresponding to (7) as another degree-4 constraint

**C4:** $v_0 \cdot (v_0 - 1) \cdot (v_0 - 2) \cdot (v_0 - 3)$

Next we have check (8)

**C5:**
$2^{2\ell} \cdot v_0 = p_0 + 2^{\ell} \cdot p_{10} - r_0 - 2^{\ell} \cdot r_1$

Up next, check (9) is a 3-bit range check

**C6:** Plookup $v_{11}$ (12-bit plookup scaled by $2^9$)

Now checks (10) and (11) can be combined into

**C7:**
$2^{\ell} \cdot (v_{11} \cdot 2^{\ell} + v_{10}) = p_2 + p_{11} + v_0 - r_2$

Next, for our use of the CRT, we must constrain that
$a \cdot b = q \cdot f + r \mod n$. Thus, check (12) is

**C8:** $a_n \cdot b_n - q_n \cdot f_n = r_n$

Next we must constrain the quotient bound addition.

Checks (13) - (16) are all combined into `multi-range-check` gadget

**C9:** `multi-range-check` $q'_0, q'_1, q'_2$ and
$q'_{01} = q'_0 + 2^{\ell} \cdot q'_1$.

Check (17) is a carry bit boolean check

**C10:** $q'_{carry01} \cdot (q'_{carry01} - 1)$

Next, check (18) is

**C11:** $2^{2\ell} \cdot q'_{carry10} = s_{01} - q'_{01}$

Finally, check (19) is

**C12:** $q'_2 = s_2 + q'_{carry01}$

The `Zero` gate has no constraints and is just used to hold values required by
the `ForeignFieldMul` gate.

# External checks

The following checks must be done with other gates to assure the soundness of
the foreign field multiplication

- Range check input
  - `multi-range-check` $a$
  - `multi-range-check` $b$
- Range check witness data
  - `multi-range-check` $q'$ and check $q_{01}' = q'_0 + 2^{\ell} q'_1$
  - `multi-range-check` $\ell$-bit limbs: $p_{10}, p_{110}, p_{111}$
- Range check output
  - `multi-range-check` either $r$ or $r'$
- Compute and constrain $r'$ the bound on $r$
  - `ForeignFieldAdd` $r + 2^t = 1 \cdot f + r'$

Copy constraints must connect the above witness cells to their respective input
cells within the corresponding external check gates witnesses.
