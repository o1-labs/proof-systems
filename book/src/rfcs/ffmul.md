# RFC: Foreign field multiplication

This document explains how we constrain foreign field multiplication in Kimchi.

## Overview

This gate constrains

$$
a \cdot b = c \mod f
$$

where $a, b, c \in \mathbb{F_f}$, a foreign field with modulus $f$, using the native field $\mathbb{F_n}$ with prime modulus $n$.

## Approach

In foreign field multiplication the foreign field modulus $f$ could be bigger or smaller than the native field modulus $n$.  When the foreign field modulus is bigger, then we need to emulate foreign field multiplication by splitting the foreign field elements up into limbs that fit into the native field element size.  When the foreign modulus is smaller everything can be constrained either in the native field or split up into limbs.

Since our projected use cases are when the foreign field modulus is bigger (more on this below) we optimize our design around this scenario.  For this case, not only must we split foreign field elements up into limbs that fit within the native field, but we must also operate in a space bigger than the foreign field.  This is because the multiplication of two foreign field elements can only be checked explicitly by constraining its quotient and remainder.  That is, we must constrain

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

Thus, the maximum size of the multiplication is quadratic in the size of foreign field.

**Naïve approach**

Naïvely, this implies that we have elements of size $f^2 - 1$ that must split them up into limbs of size at most $n$.  For example, if the foreign field modulus is $256$ and the native field modulus is $255$ bits, then we'd need $\log_2((2^{256})^2 - 1) \approx 512$ bits and, thus, require $512/255 \approx 3$ native limbs.  However, each limb cannot consume all $255$ bits of the native field element because we need space to perform arithmetic on the limbs themselves while constraining the foreign field multiplication.  Therefore, we need to choose a limb size that leaves space for performing these computations.

Later in this document (see the section entitled "Choose the limb configuration") we determine the optimal number of limbs that reduces the number of rows and gates required to constrain foreign field multiplication.  This results in $\ell = 88$ bits as our optimal limb size.  In the section about intermediate products we place some upperbounds on the number of bits required when constraining foreign field multiplication with limbs of size $\ell$ thereby proving that the computations can fit within the native field size.

Observe that by combining the naïve approach above with a limb size of $88$ bits, we would require $512/88 \approx 6$ limbs for representing foreign field elements.  Each limb is stored in a witness cell (a native field element).  However, since each limb is necessarily smaller than the native field element size, it must be copied to the range-check gate to constrain its value.  Since Kimchi only supports 7 copyable witness cells per row, this means that only one foreign field element can be stored per row.  This means a single foreign field multiplication would consume at least 4 rows (just for the operands, quotient and remainder).  This is not ideal because we want to limit the number of rows for improved performance.

**Chinese remainder theorem**

Fortunately, we can do much better than this, however, by leveraging the chinese remainder theorem (CRT for short) as we will now show.  The idea is to reduce the number of bits required by constraining our multiplication modulo two coprime moduli: $n$ and $2^t$.  Here $n$ is the native modulus and $t$ is much smaller than $512$.  By constraining the multiplication with both moduli the CRT guarantees that the constraints hold modulo $2^t \cdot n$.

All that remains is to select a value for $t$ that is big enough.  That is, we select $t$ such that $2^t \cdot n > f^2 - 1$.  As described later on in this document, by doing so we reduce the number of bits required for our use cases to $264$.  With $88$ bit limbs this means that each foreign field element only consumes $3$ witness elements, and that means the foreign field multiplication gate now only consumes $2$ rows.  The section entitled "Choose $t$" describes this in more detail.

##### 1. Parameters

* *Native field modulus* $n$
* *Foreign field modulus* $f$
* *Extra CRT modulus* $2^t$

##### 2. Choose $t$

Under the hood, we constrain $a \cdot b = q \cdot f + r \mod 2^t \cdot n$.  Since this is a multiplication in the foreign field $f$, the maximum size of $q$ and $r$ are $f - 1$, so this means

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

Instead of dynamically selecting $t$ for every $n$ and $f$ combination, we fix a $t$ that will work for the different selections of $n$ and $f$ relevant to our use cases.

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

| $n$         | $f$             | $t_{min}$ |
| ----------- | --------------- | --- |
| `vesta`     | `secp256k1`     | 258 |
| `pallas`    | `secp256k1`     | 258 |
| `vesta`     | `pallas`        | 255 |
| `pallas`    | `vesta`         | 255 |

and know that to cover our use cases we need $t \ge 258$.

Next, given our native modulus $n$ and $t$, we can compute the *maximum foreign field modulus supported*.  Actually, we compute the maximum supported bit length of the foreign field modulus $f=2^m$.

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

which is not enough space to handle anything larger than 256 bit moduli.  Instead, we will use $t=264$, giving a maximum modulus $m_{max} = 259$ bits.

##### 3. Choose the limb configuration

Choosing the right limb size and the right number of limbs is a careful balance between the number of constraints (i.e. the polynomial degree) and the witness size (i.e. the number of rows).  Because one limiting factor that we have in Kimchi is the 12-bit maximum for range check lookups, we could be tempted to introduce 12-bit limbs.  However, this would mean having many more limbs, which would consume more witness elements and require significantly more rows.  It would also increase the polynomial degree by increasing the number of constraints required for the *intermediate products* (more on this later).

We need to find a balance between the number of limbs and the size of the limbs.  The limb configuration is dependent on the value of $t$ and our maximum foreign modulus (as described in the previous section).  The larger the maximum foreign modulus, the more witness rows we will require to constrain the computation.  In particular, each limb needs to be constrained by the range check gate and, thus, must be in a copyable (i.e. permuteable) witness cell.  We have at most 7 copyable cells per row and gates can operate on at most 2 rows, meaning that we have an upperbound of at most 14 limbs per gate (or 7 limbs per row).

As stated above, we want the foreign field modulus to fit in as few rows as possible and we need to constrain operands $a, b$, the quotient $q$ and remainder $r$.  Each of these will require cells for each limb.  Thus, the number of cells required for these is

$$
cells = 4 \cdot limbs
$$

It is highly advantageous for performance to constrain foreign field multiplication with the minimal number of gates.  This not only helps limit the number of rows, but also to keep the gate selector polynomial small.  Because of all of this, we aim to constrain foreign field multiplication with a single gate (spanning at most $2$ rows).  As mentioned above, we have a maximum of 14 permuteable cells per gate, so we can compute the maximum number of limbs that fit within a single gate like this.

$$
\begin{aligned}
limbs_{max} &= cells/4 \\
      &= 14/4 \\
      &= 3.5
\end{aligned}
$$

Thus, the maximum number of limbs possible in a single gate configuration is 3.

Using $limbs_{max}=3$ and $t=264$ that covers our use cases (see the previous section), we are finally able to derive our limbs size

$$
\begin{aligned}
limb_{size} &= \frac{t}{limbs_{max}} \\
&= 264/3 \\
&= 88
\end{aligned}
$$

Therefore, our limb configuration is:

  * Limb size $\ell = 88$ bits
  * Number of limbs is $3$

##### 4. Apply CRT to constrain modulo $2^t \cdot n$

* Constrain modulo $2^t$
* Constrain modulo $n$

## Checklist

6. [x] Apply range constraints on the limbs of $a,b$ such that they are all $<2^{\ell}$
7. [x] Compute witnesses $q$ and $r$ such that $ab − qf − r = 0$.  This is an unchecked computation (i.e. there are no constraints for it) and we use the num-bigint crate, which supports arbitrary modulus sizes.  Specifically, we use its `method.div_rem` function.
8. [x] Apply range constraints on the limbs of $q,r$ such that they are all $<2^{\ell}$
9.  [x] Compute & constrain the *intermediate products*
10. [x] Compute & constrain the *$u$-value halves*
11. [x] Compute & constraint the *$v$-value witness*
12. [x] Range check $v$-values
13. [x] Use CRT to constrain that $ab - qf - r \equiv 0 \mod n$
14. [x] Range check $q$ so that $qf + r < 2^tn$
15. [ ] Open questions

## Negated modulus

Our goal is to constrain that $a \cdot b - q \cdot f = r \mod 2^t$.  Observe that the expansion of $a \cdot b - q \cdot f$ into limbs would also have subtractions between limbs, requiring our constraints to account for borrowing.  Dealing with this would create undesired complexity and increase the degree of our constraints.

In order to avoid the possibility of subtractions we instead use $a \cdot b + q \cdot f'$ where

$$
\begin{aligned}
f' &= -f \mod 2^t \\
   &= 2^t - f
\end{aligned}
$$

The negated modulus $f'$ becomes part of our constraint system and is not constrained.  Observe that $f' = f(2^t/f - 1)$ and recall that $t=264$ and $m_{max}=259$, so $2^t = 2^{5 + m_{max}} \ge 2^5 \cdot f$ and, thus, $f' > f$.

Using the substitution of the negated modulus, we now must constrain $a \cdot b + q \cdot f' = r \mod 2^t$.

## Intermediate products

We must constrain $a \cdot b + q \cdot f' = r \mod 2^t$ on the limbs, rather than as a whole.  As described above, each foreign field element $x$ is split into three 88-bit limbs: $x_0, x_1, x_2$, where $x_0$ contains the least significant bits and $x_2$ contains the most significant bits and so on.


For clarity, let $X=2^{\ell}$ and $Y=2^{2\ell}$, then expanding the right-hand side into limbs we have

$$
\begin{aligned}
&(a_0 + a_1X + a_2Y) \cdot (b_0 + b_1X + b_2Y) +  (q_0 + q_1X + q_2Y) \cdot (f'_0 + f'_1X + f'_2Y) \\
&=\\
&~~~~~ a_0b_0 + a_0b_1X + a_0b_2Y \\
&~~~~ + a_1b_0X + a_1b_1X^2 + a_1b_2XY \\
&~~~~ + a_2b_0Y + a_2b_1XY + a_2b_2Y^2 \\
&+ \\
&~~~~~ q_0f'_0 + q_0f'_1X + q_0f'_2Y \\
&~~~~ + q_1f'_0X + q_1f'_1X^2 + q_1f'_2XY \\
&~~~~ + q_2f'_0Y + q_2f'_1XY + q_2f'_2Y^2 \\
&= \\
&~~~~~ a_0b_0 + q_0f'_0\\
&~~~~ + X(a_0b_1 + a_1b_0 + q_0f'_1 + q_1f'_0) \\
&~~~~ + Y(a_0b_2 + a_2b_0 + q_0f'_2 + q_2f'_0) \\
&~~~~ + XY(a_1b_2 + a_2b_1 + q_1f'_2 + q_2f'_1) \\
&~~~~ + X^2(a_1b_1 + q_1f'_1) \\
&~~~~ + Y^2(a_2b_2 + q_2f'_2).
\end{aligned}
$$


Notice that $X^2=Y$, so the above simplifies to

$$
\begin{aligned}
&a_0b_0 + q_0f'_0 \\
&+ X(a_0b_1 + a_1b_0 + q_0f'_1 + q_1f'_0) \\
&+ Y(a_0b_2 + a_2b_0 + q_0f'_2 + q_2f'_0 + a_1b_1 + q_1f'_1) \\
&+ XY(a_1b_2 + a_2b_1 + q_1f'_2 + q_2f'_1) \\
&+ Y^2(a_2b_2 + q_2f'_2) \\
\end{aligned}
$$

Recall that $t = 264$ and observe that $XY = 2^t$ and $Y^2 = 2^t2^{88}$.  Therefore, the terms with $XY$ or $Y^2$ are a multiple of modulus and, thus, congruent to zero $\mod 2^t$. So we are left with 3 *intermediate products* that we call $p_0, p_1, p_2$:

| Term  | Scale | Product                                                  |
| ----- | ----- | -------------------------------------------------------- |
| $p_0$ | $1$   | $a_0b_0 + q_0f'_0$                                       |
| $p_1$ | $2^{\ell}$   | $a_0b_1 + a_1b_0 + q_0f'_1 + q_1f'_0$                    |
| $p_2$ | $2^{2\ell}$   | $a_0b_2 + a_2b_0 + q_0f'_2 + q_2f'_0 + a_1b_1 + q_1f'_1$ |

So far, we have introduced these checked computations to our constraints
> 1. Computation of $p_0, p_1, p_2$

## Constraints overview

Let's call $p := ab + qf' \mod 2^t$. Remember that our goal is to constrain that $p - r = 0 \mod 2^t$ (recall that any more significant bits than the 264th are ignored in $\mod 2^t$). Decomposing that claim into limbs, that means

$$
\begin{align}
2^{2\ell}(p_2 - r_2) + 2^{\ell}(p_1 - r_1) + p_0 - r_0 = 0 \mod 2^t.
\end{align}
$$

We face two challenges

*  Since $p_0, p_1, p_2$ are at least $2^{\ell}$ bits each, the terms above do not fit in $\mathbb{F}_n$ (remember $2^t > f' > f > n$)
*  The subtraction of the remainder's limbs $r_0$ and $r_1$ could require borrowing

For the moment, let's not worry about the possibility of borrows and instead focus on the first problem.

## The trick

The first problem is that our native field is too small to constrain (1).  The trick to overcoming this is to assume a space large enough to hold the computation, view the outcome in binary and then split it up into chunks that fit in the native modulus.

To this end, it helps to know how many bits these intermediate products require.  On the left side of the equation, $p_0$  is at most $2\ell + 1$ bits.  We can compute this by substituting the maximum possible binary values (all bits set to 1) into $p_0 = a_0b_0 + q_0f'_0$ like this

$$
\begin{aligned}
\mathsf{maxbits}(p_0) &= \log_2(\underbrace{(2^{\ell} - 1)}_{a_0}\underbrace{(2^{\ell} - 1)}_{b_0} + \underbrace{(2^{\ell} - 1)}_{q_0}\underbrace{(2^{\ell} - 1)}_{f'_0}) \\
&= \log_2(2(2^{2\ell} - 2^{\ell + 1} + 1)) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2).
\end{aligned}
$$

So $p_0$ fits in $2\ell + 1$ bits.  Similarly, $p_1$ needs at most $2\ell + 2$ bits and $p_2$ is at most $2\ell + 3$ bits.


| Term     | $p_0$       | $p_1$       | $p_2$       |
| -------- | ----------- | ----------- | ----------- |
| **Bits** | $2\ell + 1$ | $2\ell + 2$ | $2\ell + 3$ |

The diagram below shows the right hand side of this equality (i.e. the value $p - r$). Let's look at how the different bits of $p_0, p_1, p_2, r_0, r_1$ and $r_2$ impact it.

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
             ≈ u0                           ≈ u1
```

Within our native field modulus we can fit up to $2\ell + \delta < \log_2(n)$ bits, for small values of $\delta$ (but sufficient for our case).  Thus, we can only constrain approximately half of $p - r$ at a time. In the diagram above the vertical line at 2L bisects $p - r$ into two $\approx2\ell$ bit values: $u0$ and $u1$ (the exact definition of these values follow).  Our goal is to constrain $u_0$ and $u_1$.

## Computing the zero-sum halves: $u_0$ and $u_1$

Now we can derive how to compute $u0$ and $u1$ from $p$ and $r$.

The direct approach would be to bisect both $p_0$ and $p_1$ and then define $u_0$ as just the sum of the $2\ell$ lower bits of $p_0$ and $p_1$ minus $r_0$ and $r_1$.  Similarly $u_1$ would be just the sum of upper bits of $p_0, p_1$ and $p_2$ minus $r_2$.  However, each bisection requires constraints for the decomposition and range checks for the two halves.  Thus, we would like to avoid bisections are they are expensive.

Ideally, if our $p$'s lined up on the $2\ell$ boundary, we would not need to bisect at all.  However, we are unlucky and it seems like we must bisect both $p_0$ and $p_1$.  Fortunately, we can at least avoid bisecting $p_0$ by allowing it to be summed into $u_0$ like this

$$
u_0 = p_0 + 2^{\ell}\cdot p_{10} - r_0 - 2^{\ell}\cdot r_1
$$

Note that $u_0$ is actually greater than $2\ell$ bits in length.  This may not only be because it contains $p_0$ whose length is $2\ell + 1$, but also because adding $p_{10}$ may cause an overflow.  The maximum length of $u_0$ is computed by substituting in the maximum possible binary value of $2^{\ell} - 1$ for the added terms and $0$ for the subtracted terms of the above equation.

$$
\begin{aligned}
\mathsf{maxbits}(u_0) &= \log_2(\underbrace{(2^{\ell} - 1)(2^{\ell} - 1) + (2^{\ell} - 1)(2^{\ell} - 1)}_{p_0} + \underbrace{2^{\ell} \cdot (2^{\ell} - 1)}_{p_{10}}) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2 + 2^{2\ell} - 2^\ell) \\
&= \log_2( 3\cdot 2^{2\ell} - 5 \cdot 2^\ell +2 ) \\
\end{aligned}
$$

which is $2\ell + 2$ bits.

Next, we compute $u_1$ as

$$
u_1 = p_{11} + p_2 - r_2
$$

The maximum size of $u_1$ is computed as

$$
\begin{aligned}
\mathsf{maxbits}(u_1) &= \mathsf{maxbits}(p_{11} + p_2)
\end{aligned}
$$

In order to obtain the maximum value of $p_{11}$, we define $p_{11} := \frac{p_1}{2^\ell}$. Since the maximum value of $p_1$ was $2^{2\ell+2}-2^{\ell+3}+4$, then the maximum value of $p_{11}$ is $2^{\ell+2}-8$. For $p_2$, the maximum value was $6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6$, and thus:

$$
\begin{aligned}
\mathsf{maxbits}(u_1) &= log_2(\underbrace{2^{\ell+2}-8}_{p_{11}} + \underbrace{6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6}_{p_2}) \\
&= \log_2(6\cdot 2^{2\ell} - 8 \cdot 2^\ell - 2) \\
\end{aligned}
$$

which is $2\ell + 3$ bits.

| Term     | $u_0$       | $u_1$       |
| -------- | ----------- | ----------- |
| **Bits** | $2\ell + 2$ | $2\ell + 3$ |

Thus far we have the following constraints
> 2. Composition of $p_{10}$ and $p_{11}$ result in $p_1$
> 3. Range check $p_{11} \in [0, 2^{\ell + 2})$
> 4. Range check $p_{10} \in [0, 2^{\ell})$

For the next step we would like to constrain $u_0$ and $u_1$ to zero.  Unfortunately, we are not able to do this!

* Firstly, as defined $u_0$ may not be zero because we have not bisected it precisely at $2\ell$ bits, but have allowed it to contain the full $2\ell + 2$ bits.  Recall that these two additional bits are because $p_0$ is at most $2\ell + 1$ bits long, but also because adding $p_{10}$ increases it to $2\ell + 2$.  These two additional bits are not part of the first $2\ell$ bits of $p - r$ and, thus, are not necessarily zero.  That is, they are copied from the second $2\ell$ bits (i.e. $u_1$).

* Secondly, whilst the highest $\ell + 3$ bits of $p - r$ would wrap to zero $\mod 2^t$, when placed into the smaller $2\ell + 3$ bit $u_1$ in the native field, this wrapping does not happen.  Thus, $u_1$'s $\ell + 3$ highest bits may be nonzero.

We can deal with this non-zero issue by computing carry witness values.

## Computing carry witnesses values $v_0$ and $v_1$

Thus, instead of constraining $u_0$ and $u_1$ to zero, there must be satisfying witness $v_0$ and $v_1$ such that the following constraints hold.
> 5. There exists $v_0$ such that $u_0 = v_0 \cdot 2^{2\ell}$
> 6. There exists $v_1$ such that $u_1 + v_0 = v_1 \cdot 2^{\ell}$

Here $v_0$ is the last two bits of $u_0$'s $2\ell + 2$ bits, i.e., the result of adding the highest bit of $p_0$ and any possible carry bit from the operation of $u_0$.  Similarly, $v_1$ corresponds to the highest $\ell + 3$ bits of $u_1$.

Remember we only need to prove the first $3\ell$ bits of $p - r$ are zero, since everything is $\mod 2^t$ and  $t = 3\ell$.  It may not be clear how this prefix witness approach, proves the $3\ell$ bits are indeed zero because within $u_0$ and $u_1$ there are bits that are nonzero.  The key observation is that these bits are too high for $\mod 2^t$.

By making the prefix argument with $v_0$ and $v_1$ we are proving that $u_0$ is something prefixed with $2\ell$ zeros and that $u_1$ is something prefixed with $\ell$ zeros.  Any nonzero bits after $3\ell$ do not matter, since everything is $\mod 2^t$.

All that remains is to range check $v_0$ and $v_1$
> 7. Range check $v_0 \in [0, 3]$
> 8. Range check $v_1 =\in [0, 2^{\ell + 3})$

## Subtractions

Now let's revisit our second problem, the possibility of borrows when subtracting the limbs of the remainder.  In order to constrain

$$
2^{2\ell}(p_2 - r_2) + 2^{\ell}(p_1 - r_1) + p_0 - r_0 = 0 \mod 2^t.
$$

we end up with some subtractions on the limbs.  As we previously mentioned, this a complexity we would like to avoid.  If our overall approach were to constrain this directly (i.e. if we had enough space in $\mathbb{F_n}$), then we would keep track of borrow bits $c_i$ for each limb $i$.  For example, we'd have constraints like

$$
\begin{aligned}
a_0 \cdot b_0 &= q_0 \cdot f'_0 + r_0 - c_0 \cdot 2^{2\ell + 1} \\
a_1 \cdot b_1 &= q_1 \cdot f'_1 + r_1 - c_1 \cdot 2^{2\ell + 1} + c_0 \\
a_2 \cdot b_2 &= q_2 \cdot f'_2 + r_2 + c_1
\end{aligned}
$$

However, in our approach with $u_0$ and $u_1$ things are different.  We have

$$
\begin{aligned}
u_0 &= p_0 + 2^{\ell}\cdot p_{10} - r_0 - 2^{\ell}\cdot r_1 \\
&= 2^{\ell}(p_{10} - r_1) + p_0 - r_0
\end{aligned}
$$

where $p_0 - r_0$ is $2\ell + 1$ bits and $2^{\ell}(p_{10} - r_1)$ is $2\ell$ bits.  Let's consider each possible underflow.

Firstly, if $p_0 - r_0$ created an underflow we would borrow from $p_1 - r_1$ by adding $2^{2\ell + 1}$ to $p_0 - r_0$ and subtracting $1$ from $p_1 - r_1$.  However, recall that according to our definition of $u_0$, we already added to it the lowest $\ell$ bits of $p_1$ (i.e. $p_{10}$) and all of $r_1$.  So, we've already have added the bits we would borrow.  Thus, no borrowing is needed here because it already implicitly accounted for.

Secondly, for $p_{10} - r_1$, we could borrow from $p_{11}$ or $p_2 - r_2$.  This is the same as saying, we'd borrow from $p_{11} + p_2 - r_2 = u_1$.  Thus, we would add $2^{2\ell}$ to $p_{10} - r_1$ and subtract $1$ from $u_1$.  Thus, the constraint becomes

$$
u_0 = 2^{\ell}(p_{10} - r_1) + p_0 - r_0 - c_0 \cdot 2^{2\ell}
$$

For $u_1$ it's not possible for $r_2 > p_2$ and, therefore, the most significant borrow bit $c_1$ should always be zero.  Thus, $u_1$'s constraint is

$$
u_1 = p_{11} + p_2 - r_2 + c_0
$$

**Costs:**

Range checks should be the dominant cost, let's see how many we have.

Range check (3) requires two range checks for $p_{11} = p_{111} \cdot 2^\ell + p_{110}$
 * a) $p_{110} \in [0..2^\ell)$
 * b) $p_{111} \in [0,3]$

Range check (8) requires two range checks and a decomposition check that is merged in (6).
 * a) $v_{10} \in [0, 2^{\ell})$
 * b) $v_{11} \in [0, 7]$

The range checks on $p_0, p_1$ and $p_2$ follow from the range checks on $a,b$ and $q$.

So we have 3.a, 3.b, 4, 7, 8.a, 8.b.

| Range check | Gate type(s)                               | Witness                   | Rows |
| ----------- | ------------------------------------------ | ------------------------- | ---- |
| 7           | $(v_0 - 3)(v_0 - 2)(v_0 - 1)v_0$           | $v_0$                     | < 1  |
| 3.a         | $(p_{111} - 3)(p_{111} - 2)(p_{111} - 1)q$ | $p_{111}$                 | < 1  |
| 8.b         | degree-8 constraint or plookup             | $v_{11}$                  | 1    |
| 3.b, 4, 8.a | multi-range-check                          | $p_{10}, p_{110}, v_{10}$ | 4    |

So we have 1 multi-range-check, 1 single-range-check and 2 low-degree range checks. This consumes just over 5 rows.

## Use CRT to constrain $ab - qf - r \equiv 0 \mod n$

We check $ab - qf - r \equiv 0 \mod n$, which is over $\mathbb{F}_n$.

This gives us equality $\mod 2^t \cdot n$ as long as the divisors are coprime.  That is, as long as $\mathsf{gcd}(2^t, n) = 1$.  Since the native modulus $n$ is prime, this is true.

Thus, to perform this check is simple.  We compute

$$
\begin{aligned}
a' &= a \mod n \\
b' &= b \mod n \\
q' &= q \mod n \\
f'' &= f \mod n \\
r' &= r \mod n
\end{aligned}
$$

and then constrain

$$
a' \cdot b' - q' \cdot f'' - r' = 0 \mod n.
$$

> 9. $a' \cdot b' - q' \cdot f'' - r' = 0 \mod n$

## Range check $q$ so that $q \cdot f + r < 2^t \cdot n$

> The reason this range constraint is needed is that the CRT allows us to verify the desired equality $ab = qf + r$ as integers only when both side of the equation are smaller than $2^t \cdot n$.

In our specific case, $t=264$, $n < 2^{255}$ and $f < 2^{256}$. Then, we can create a constraint for our case that is sufficient to check the above. Concretely, if $q$ was such that $q < 2^{256}$ (even if potentially larger than $f$), we can see that the above claim holds.

If $q < 2^{256}$, and since $f < 2^{256}$ as well, then the main check becomes:

$$
\begin{aligned}
  q f + r &< 2^{256} \cdot 2^{256} + 2^{264} = 2^{512} + 2^{264}\\
  2^t \cdot n &< 2^{264} \cdot 2^{255} \\
  &\implies \\
  2^{264} \cdot (2^{248} + 1) &< 2^{264}\cdot 2^{255} \\
  &\equiv\\
  (2^{248} + 1) &<  2^{255} \\
   &\implies \\
   q f + r &<  2^t \cdot n \quad \text{ if } \quad q < 2^{256}
\end{aligned}
$$

Note that the above condition holds by far,

Value $r < f$, so we can check

$$
\begin{aligned}
qf + r < qf + f - 1 < qf + f = f(q + 1) &< >2^tn \\
q &< 2^t\frac{n}{f} - 1.
\end{aligned}
$$

However, maybe we should just check

$$
q < f
$$

and

$$
f < 2^t
$$

instead.


## Constraints

Now we collect all of the constraints that the FFMul gadget will need.

### 1. Range constrain $a < 2^{264}$

* [x] These rows check for each of the 3 limbs of $a$ that they are $< 2^{88}$.  `multi-range-check-0`

### 2. Range constrain $b < 2^{264}$

* [x] These rows check for each of the 3 limbs of $b$ that they are $< 2^{88}$. `multi-range-check-1`

### 3. Range constrain $q < 2^{256}$

We have to range constrain witness $q$ to be $<2^{264}$, but also $2^{256}$ for the correctness of the CRT. Then, for both of them, it is sufficient to check $q<2^{256}$. We can do this by using the range check gadget. In particular we can check if $q \cdot 2^8 < 2^{264}$. This will only affect the most significant limb of $q$, so the check becomes to constrain that the 8 leading bits of the 12-bit most significant sublimb of $q$ are zero or not. Nonetheless, in order to avoid field elements from overflowing, we also have to check for soundness if the original sublimb was also contained in 12 bits. Meaning:

- [x] Range check $q < 2^{264}$ as usual (including MSB limb $< 2^{88}$) `multi-range-check-2`
- [x] Additionally, check if MS sublimb $q_2$ multiplied by $2^8$ is a 12-bit number (equivalent to checking that the MSB limb is $<2^{80}$). `Zero`

### 4. Range constrain $r < 2^{264}$

* [x] These rows check for each of the 3 limbs of $r$ that they are $< 2^{88}$. `multi-range-check-3`

### 5. Intermediate products

Compute/Constrain intermediate products $p_0$, $p_1$, and $p_2$ as:

- [x] $p_0 = a_0 \cdot b_0 - q_0 \cdot f_0$ `ForeignFieldMul`
- [x] $p_1 = a_0 \cdot b_1 + a_1 \cdot b_0 - q_0 \cdot f_1 - q_1 \cdot f_0$ `ForeignFieldMul`
- [x] $p_2 = a_0 \cdot b_2 + a_2 \cdot b_0 + a_1 \cdot b_1 - q_0 \cdot f_2 - q_2 \cdot f_0 - q_1 \cdot f_1$ `ForeignFieldMul`

where each of them is about $2\ell$-length elements.

### 6. Decompose middle intermediate product

Check that $p_{11} | p_{10} = p_1$:

- [x] $p_1 = 2^\ell \cdot p_{11} + p_{10}$ `ForeignFieldMul`
- [x] Range check $p_{10} < 2^\ell$ `multi-range-check-4`
- [x] Range check $p_{11} < 2^{\ell+2}$
    - [x] $p_{11} = p_{111} \cdot 2^\ell + p_{110}$  `ForeignFieldMul`
    - [x] Range check $p_{110} < 2^\ell$ `multi-range-check-4`
    - [x] Range check $p_{111} < 2^2$ `ForeignFieldMul`

Altogether, step 6 (and the second constraint of step 5) can be combined into the following 4 constraints:

- $2^\ell \cdot ( 2^\ell \cdot p_{111} + p_{110} ) + p_{10} = a_0 \cdot b_1 + a_1 \cdot b_0 - q_0 \cdot f_1 - q_1 \cdot f_0$
- Range check $p_{10} < 2^\ell$
- Range check $p_{110} < 2^\ell$
- Range check $p_{111} \in [0, 2^2)$ with a degree-4 constraint

and $p_{11}$ does not need to be in the witness but we can define it as an expression.

### 7. Zero sum

Now we have to constrain the zero sum:

$$(p_0 - r_0) + 2^{88}(p_1 - r_1) + 2^{176}(p_2 - r_2) = 0$$

We constrain the first and the second halves as:

- [x] $v_0 \cdot 2^{2\ell} = p_0 + 2^\ell \cdot p_{10} - r_0 - 2^\ell \cdot r_1$ `ForeignFieldMul`
- [x] $v_1 \cdot 2^{\ell} = (p_{111} \cdot 2^\ell + p_{110}) + p_2 - r_2 + v_0$ `ForeignFieldMul`

And some more range constraints

- [x] Check that $v_0 \in [0, 3]$ with a degree-4 constraint `ForeignFieldMul`
- [x] Check that $v_1 \in [0, 2^{\ell + 3})$
    - [x] Check/substitute/let $v_1 = v_{11} \cdot 2^{88} + v_{10}$ `ForeignFieldMul`
    - [x] Check $v_{11} \in [0,7]$ `ForeignFieldMul`
    - [x] Check $v_{10} < 2^\ell$ with range constraint `multi-range-check-4`

# Layout

Based on the constraints above, we need the following 12 values copied from the range check gates.

```
a0, a1, a2, b0, b1, b2, q0, q1, q2, r0, r1, r2
```
Since we need 12 copied values for the constraints the constraints must span 2 rows.  N.b. the $f$ and $g$ values are gobally accessible in the `ConstraintSystem`

|            | Curr                                | Next         |
| ---------- | ----------------------------------- | ------------ |
| **Column** | `ForeignFieldMul`                   | `Zero`       |
| 0          | $a_0$ (copy)                        | $a_2$ (copy) |
| 1          | $a_1$ (copy)                        | $b_0$ (copy) |
| 2          | $\mathsf{shift}_{v_{11}}$ (plookup) | $b_1$ (copy) |
| 3          | $\mathsf{shift}_{q_2}$ (plookup)    | $b_2$ (copy) |
| 4          | $q_0$ (copy)                        | $r_0$ (copy) |
| 5          | $q_1$ (copy)                        | $r_1$ (copy) |
| 6          | $q_2$ (copy)                        | $r_2$ (copy) |
| 7          | $p_{10}$                            |
| 8          | $p_{110}$                           |
| 9          | $p_{111}$                           |
| 10         | $v_0$                               |
| 11         | $v_{10}$                            |
| 12         | $v_{11}$                            |
| 13         |                                     |
| 14         |                                     |

where $\mathsf{shift}_{v_{11}} = 2^9v_{11}$ and $\mathsf{shift}_{q_2} = 2^8q_2$.


`ForeignFieldMul` has the following intermediate computations
  1. $p_0 = a_0b_0 - q_0f_0$
  2. $p_1 = a_0b_1 + a_1b_0 - q_0f_1 - q_1f_0$
  3. $p_2 = a_0b_2 + a_2b_0 + a_1b_1 - q_0f_2 - q_2f_0 - q_1f_1$

and the following constraints

1. $p_1 = 2^{\ell}p_{11} + p_{10}$
2. $p_{11} = 2^{\ell}p_{111} + p_{110}$
3. $v_1 = 2^{88}v_{11} + v_{10}$
4. $2^{2\ell}v_0 = p_0 + 2^{\ell}p_{10} - r_0 - 2^{\ell}r_1$
5. $2^{\ell}v_1 = v_0 + p_{11} + p_2 - r_2$
6. $v_0 \in [0, 2^2)$
7. $p_{111} \in [0, 2^2)$
8. $v_{11} \in [0, 2^3)$
9. $q_2 \in [0, 2^4)$
10. $2^9v_{11} = \mathsf{shift}_{v_{11}}$
11. $2^8 q_2 = \mathsf{shift}_{q_2}$

As mentioned above, constraints (1), (2), and (3) can be combined inside (5) to get constraint (3) below and, thus, only 9 constraints total:

1. $p_1 = 2^{\ell}(2^{\ell}p_{111} + p_{110}) + p_{10}$
2. $2^{2\ell}v_0 = p_0 + 2^{\ell}p_{10} - r_0 - 2^{\ell}r_1$
3. $2^{\ell}(2^{88}v_{11} + v_{10}) = v_0 + (2^{\ell}p_{111} + p_{110}) + p_2 - r_2$
4. $2^9v_{11} = \mathsf{shift}_{v_{11}}$
5. $2^8 q_2 = \mathsf{shift}_{q_2}$
6. $v_0 \in [0, 2^2)$
7. $p_{111} \in [0, 2^2)$
8. $v_{11} \in [0, 2^3)$
9. $q_2 \in [0, 2^4)$

The `ForeignFieldMul` gate performs the first 7 constraints, plus the 2 plookups, corresponding to (8) and (9) above.

Note that $p_0, p_1$ and $p_2$ do not need to be part of the witness.

The `Zero` gate itself has no constraints.

These 2 gates are preceeded by 5 multi-range-check gates.

## Layout

| Row(s) | Gate type(s)        | Witness                   |
| ------ | ------------------- | ------------------------- |
| 0-3    | `multi-range-check` | $a$                       |
| 4-7    | `multi-range-check` | $b$                       |
| 8-11   | `multi-range-check` | $q$                       |
| 12-15  | `multi-range-check` | $r$                       |
| 16-19  | `multi-range-check` | $p_{10}, p_{110}, v_{10}$ |
| 20     | `ForeignFieldMul`   |                           |
| 21     | `Zero`              |                           |

# Underflows

In the above, we have used arithmetics from the point of view of the bitstrings behind these limbs. Nonetheless, they will ultimately be interpreted as native field elements. This entails no problems when we are dealing with "positive" values. However, when we subtract a "larger" value from a "smaller" value, the result will be negative. And these numbers cause wraps around the native modulus. In other words, the "minus" sign that we would normally encode in integers, gets translated as a huge field element that overflows the limb length.

For this reason, when we come across subtraction (which we do when computing the intermediate products), we must include some additional conditionals to ensure that we do not cause underflows. We will include in the witness three auxiliary values (one per intermediate product) to take care of this. Whenever the subtracted part is larger than the summand, we will add a power of two (a 1 bit followed by a sufficient number of 0 bits) to the operation to obtain the correct bitstring up to the suffix that we are intersted in. Then, this amount will be deduced from the next intermediate product with a correct shift to make sure that the result is aligned.

A bit more visually, we will modify the per-limb operations as follows:

```text
0             L             2L            3L            4L
|-------------|-------------|-------------|-------------|-------------|
                            :
|--------------p0-----------:-| 2L + 1
                            :
00------------------------00:01 <- aux0
                            :
                            :
              |-------------:-p1------------| 2L + 2
                    p10➚    :        p11➚
                            :
              00--------------------------00:001 <- aux1
                            :
                            |----------------p2-------------| 2L + 3
                            :
                            00----------------------------00:0001 <- aux2
                            :
|-----r0------|             :
                            :
              |-----r1------|
                            :
                            |-----r2------|
\__________________________/ \______________________________/
             ≈ u0                           ≈ u1
```
This means,
- if `aux0` is set to `1`, then $2^{2L + 1}$ will be added to `p0` and `2` will be subtracted from the top term.
- if `aux1` is set to `1`, then $2^{2L + 2}$ will be added to `p1` and $2^{L+2}$ will be subtracted from the top term.
- if `aux2` is set to `1`, then $2^{2L + 3}$ will be added to `p2` and $2^{L+3}$.


<!--
## Another approach

Split $u_0$ and go direct!

> 2. Composition of $p_{00}$ and $p_{01}$ = $p_0$
> 3. Range check $p_{00} \in [0, 2^{2\ell})$
> 4. Range check $p_{01} \in [0,1]$
> 5. Composition of $p_{10}$ and $p_{11}$ = $p_1$
> 6. Range check $p_{11} \in [0, 2^{\ell})$
> 7. Range check $p_{10} \in [0, 2^{\ell + 2})$

Now

\begin{aligned}
u_0 &= p_{00} + p_{10} - r_0 - 2^{\ell}r_1 \\
u_1 &= p_{01} + p_{11} + p_2 - r_2
\end{aligned}

Here


\begin{aligned}
\mathsf{maxbits}(u_0) &= \log_2(2^{2\ell} - 1 + 2^{\ell} - 1) \\
&= 2\ell \\
\mathsf{maxbits}(u_1) &= \log_2(1 + 2^{\ell + 2} - 1 + 2^{2\ell + 3}) \\
&= 2\ell + 3
\end{aligned}

Both $u_0$ and $u_1$ fit in the native field (i.e. their length in bits is at most $2\ell + \delta < \log_2(n)$), so the final constraints are
> 8. Check $u_0 = 0$
> 9. Check $u_1 \mod 2^{\ell} = 0$ ?

If they are zero, then we don't need to range check them.

**Cost:** Here we have 4 range checks, but range check (4) is a trivial degree 2 constraint.  So, there are actually 3 range checks.  Range checks (3) and (6) fit into a single multi-range-check gate and (7) requires a single range check gate followed by a degree 4 constraint.  So the constraints would look like this

| Range check | Gate type(s)                                 | Witness          | Rows |
| ----------- | -------------------------------------------- | ---------------- | ---- |
| 4           | $(p_{01} - 1)p_{01}$                         | $p_{01}$         | < 1  |
| 7           | $(p_{10} - 3)(p_{10} - 2)(p_{10} - 1)p_{10}$ | $p_{10}$         | < 1  |
| 3,6         | multi-range-check                            | $p_{00}, p_{11}$ | 4    |
| 7           | single-range-check (`RangeCheck0`)           | $p_{10}$         | 1    |

These range-checks should be the dominant cost.

So we have 1 multi-range-check, 1 single-range-check and 2 low-degree range checks.  This consumes just over 5 rows.

Thus, in terms of range-checks the cost of this approach is the same.

The only overhead are some extra terms for the composition (2).  But this assumes the original approach doesn't need to also range check $u_0$ and $u_1$, nor explicitly check they are zero.
-->

## Open questions

1. How does this guarantee anything about foreign modulus $f$?

   Neither by CRT, nor by $2^tn > f^2 + f$ bound, is it clear (to me) how these checks tie back to the foreign field modulus.

   > r is in the class of solutions of c, so as soon as r goes to a foreign field machine it is compressed back to c.

2. Similar to question (1), why don't we need to range check $r$ at the end?

3. Are these range checks of limbs really accurate? (related to above)

4. Why don't we range check $a,b < f$ (also related to above)?

a. Specifically, we have to check that $q\cdot f + r < 2^t \cdot n$ for the CRT, but also that $a\cdot b < 2^t \cdot n$. Thanks to the multi range check, we know that $a < 2^t$ and $b < 2^t$. Thus, since by definition $2^t > n$, this seems not to suffice to know that $a\cdot b < 2^t \cdot n$. Nonetheless, if we assume $a < f$ and $b < f$, since $n < f < 2^t$ and $t$ is said to be chosen such that $2^t \cdot n > f^2$, then we have that $a \cdot b < 2^t \cdot n$.

b. But we are not proving that $a$ or $b$ are in $F_f$, nor $t$ being such a number. In particular, if we could assume that $a$ and $b$ are in $F_f$, wouldn't we know already that $q$ must be $< f$? Ok, no because we are in a field, you could have more solutions, right?

5. Our common cases for the foreign field are secp256k1 or Vesta/Pallas with native field either Pallas or Vesta. Since our common cases are at most 1 bit larger than our native fields, then could we obtain better performance with a special implementation geared to at most 1 bit difference in modulus size?

## Answers

We met with Matthew and we discussed these questions with him. As long as we check off-gate that the initial multiplicands $a,b$ and final remainder $r$ (it may be the case that we have a chain of multiplications) belong to the foreign field, then it should be fine.