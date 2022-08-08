# RFC: Foreign field multiplication

This document outlines the steps needed to constrain foreign field multiplication in Kimchi.

## Overview

1. [x] Parameters
    * $\ell = 88$ bits
    *  $n$ is *native field modulus*
    *  $f$ is *foreign field modulus*
1. [x] Choose $t$ such that $2^tn > f^2$
> $t = 2\log_2(f) - \log_2(n)$

| $n$         | $f$             | $t$ |
| ----------- | --------------- | --- |
| Pasta (255) | secp256k1 (256) | 257 |
| Pasta (255) | Pasta (255)     | 255 |

Note: Note that for this scheme to work we also need $t$ such that $2^tn > p^2 + p$.

However, since $\ell$ is fixed to 88-bits and we have 3 limbs per foreign field element, we choose $t=88*3=264$, which satisfies the requirements above.


3. [x] Apply range constraints on the limbs of $a,b$ such that they are all $<2^{\ell}$
4. [x] Compute witnesses $q$ and $r$ such that $ab − qf − r = 0$.  This is an unchecked computation (i.e. there are no constraints for it) and we use the num-bigint crate, which supports arbitrary modulus sizes.  Specifically, we use its `method.div_rem` function.
5. [x] Apply range constraints on the limbs of $q,r$ such that they are all $<2^{\ell}$
6. [x] Compute & constrain the *intermediate products*
7. [x] Compute & constrain the *$u$-value halves*
8. [x] Compute & constraint the *$v$-value witness*
9. [x] Range check $v$-values
10. [x] Use CRT to constrain that $ab - qf - r \equiv 0 \mod n$
11. [x] Range check $q$ so that $qf + r < 2^tn$ 
12. [ ] Open questions

## Intermediate products

Each foreign field element $x$ is split into three 88-bit limbs: $x_0, x_1, x_2$

Given foreign field elements $a,b$, we need to evaluate $ab - qf \mod 2^t$.

For some reason (perhaps to make it simpler) we actually evaluate $ab + qg$ where

$$
g = -f \mod 2^t.
$$

The expansion of $ab + qg$ is

\begin{aligned}
&(a_0 + a_1X + a_2Y)(b_0 + b_1X + b_2Y) +  (q_0 + q_1X + q_2Y)(g_0 + g_1X + g_2Y) \\
&=\\
&~~~~~ a_0b_0 + a_0b_1X + a_0b_2Y \\
&~~~~ + a_1b_0X + a_1b_1X^2 + a_1b_2XY \\
&~~~~ + a_2b_0Y + a_2b_1XY + a_2b_2Y^2 \\
&+ \\
&~~~~~ q_0g_0 + q_0g_1X + q_0g_2Y \\
&~~~~ + q_1g_0X + q_1g_1X^2 + q_1g_2XY \\
&~~~~ + q_2g_0Y + q_2g_1XY + q_2g_2Y^2 \\
&= \\
&~~~~~ a_0b_0 + q_0g_0 \\
&~~~~ + X(a_0b_1 + a_1b_0 + q_0g_1 + q_1g_0) \\
&~~~~ + Y(a_0b_2 + a_2b_0 + q_0g_2 + q_2g_0) \\
&~~~~ + XY(a_1b_2 + a_2b_1 + q_1g_2 + q_2g_1) \\
&~~~~ + X^2(a_1b_1 + q_1g_1) \\
&~~~~ + Y^2(a_2b_2 + q_2g_2)
\end{aligned}

where $X=2^{88}$ and $Y=2^{176}$.


Notice that $X^2=Y$, so the above simplifies to

\begin{aligned}
&a_0b_0 + q_0g_0 \\
&+ X(a_0b_1 + a_1b_0 + q_0g_1 + q_1g_0) \\
&+ Y(a_0b_2 + a_2b_0 + q_0g_2 + q_2g_0 + a_1b_1 + q_1g_1) \\
&+ XY(a_1b_2 + a_2b_1 + q_1g_2 + q_2g_1) \\
&+ Y^2(a_2b_2 + q_2g_2) \\
\end{aligned}

Recall that $t = 264$ and observe that $XY = 2^t$ and $Y^2 = 2^t2^{88}$.  Therefore, the terms with $XY$ or $Y^2$ are a multiple of modulus and, thus, congruent to zero $\mod 2^t$. So we are left with 3 intermediate products that we call $p_0, p_1, p_2$:

| Term  | Scale | Product                                               |
| ----- | ----- | ----------------------------------------------------- |
| $p_0$ | $1$   | $a_0b_0 + q_0g_0$                                     |
| $p_1$ | $X$   | $a_0b_1 + a_1b_0 + q_0g_1 + q_1g_0$                   |
| $p_2$ | $Y$   | $a_0b_2 + a_2b_0 + q_0g_2 + q_2g_0 + a_1b_1 + q_1g_1$ |

So far, we have introduced these checked computations to our constraints
> 1. Computation of $p_0, p_1, p_2$

Let's call $p:= ab + qg \mod 2^t$. Remember that our goal at this point was to constrain that $p - r = 0 \mod 2^t$ (note that any more significant bits than the 264th are ignored in $\mod 2^t$). Decomposing that claim, that means

$$
r_0+2^{88}r_1+2^{176}r_2 = p_0+2^{88}p_1+2^{176}p_2,
$$

except that in $\mathbb{F}_n$, those terms do not fit and we have to find a way around it (since $2^t>f>n$ we seem to have the same problem as initially, but in fact we are getting closer to the solution).

We must constrain that
$$
p_0+2^{\ell}p_1+2^{2\ell}p_2 - r_0-2^{\ell}r_1-2^{2\ell}r_2 = 0.
$$

It helps to know how many bits these intermediate products require.  On the left side of the equation, $p_0$  is at most $2\ell + 1$ bits.  We can compute this by substituting the maximum possible binary values (all bits set to 1) into $p_0 = a_0b_0 + q_0g_0$ like this
\begin{aligned}
\mathsf{maxbits}(p_0) &= \log_2(\underbrace{(2^{\ell} - 1)}_{a_0}\underbrace{(2^{\ell} - 1)}_{b_0} + \underbrace{(2^{\ell} - 1)}_{q_0}\underbrace{(2^{\ell} - 1)}_{g_0}) \\
&= \log_2(2(2^{2\ell} - 2^{\ell + 1} + 1)) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2).
\end{aligned}
So $p_0$ fits in $2\ell + 1$ bits.  Similarly, the $p_1$ needs at most $2\ell + 2$ bits and $p_2$ takes at most $2\ell + 3$ bits.

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

Within our native field modulus we can fit up to $2\ell + \delta < \log_2(n)$ bits, for small values of $\delta$ (but sufficient for our case).  Thus, we can only constrain approximately half of $p - r$ at a time. In the diagram above the vertical line at 2L bisects $p - r$ into two $\approx2\ell$ bit values: $u0$ and $u1$ (the exact definition of these values follow).

## Computing the zero-sum halves: $u_0$ and $u_1$

Now we can derive how to compute $u0$ and $u1$ from $p$ and $r$.

The direct approach would be to bisect both $p_0$ and $p_1$ and then define $u_0$ as just the sum of the $2\ell$ lower bits of $p_0$ and $p_1$ minus $r_0$ and $r_1$.  Similarly $u_1$ would be just the sum of upper bits of $p_0, p_1$ and $p_2$ minus $r_2$.  However, each bisection requires constraints for the decomposition and range checks for the two halves.  Thus, we would like to avoid bisections are they are expensive.

Ideally, if our $p$'s lined up on the $2\ell$ boundary, we would not need to bisect at all.  However, we are unlucky and it seems like we must bisect both $p_0$ and $p_1$.  Fortunately, we can at least avoid bisecting $p_0$ by allowing it to be summed into $u_0$ like this

$$
u_0 = p_0 + 2^{\ell}\cdot p_{10} - r_0 - 2^{\ell}\cdot r_1
$$

Note that $u_0$ is actually greater than $2\ell$ bits in length.  This may not only be because it contains $p_0$ whose length is $2\ell + 1$, but also because adding $p_{10}$ may cause an overflow.  The maximum length of $u_0$ is computed by substituting in the maximum possible binary value of $2^{\ell} - 1$ for the added terms and $0$ for the subtracted terms of the above equation.

\begin{align}
\mathsf{maxbits}(u_0) &= \log_2(\underbrace{(2^{\ell} - 1)(2^{\ell} - 1) + (2^{\ell} - 1)(2^{\ell} - 1)}_{p_0} + \underbrace{2^{\ell} \cdot (2^{\ell} - 1)}_{p_{10}}) \\
&= \log_2(2^{2\ell + 1} - 2^{\ell + 2} + 2 + 2^{2\ell} - 2^\ell) \\
&= \log_2( 3\cdot 2^{2\ell} - 5 \cdot 2^\ell +2 ) \\
\end{align}
which is $2\ell + 2$ bits.


Next, we compute $u_1$ as

$$
u_1 = p_{11} + p_2 - r_2
$$

The maximum size of $u_1$ is computed as

\begin{align}
\mathsf{maxbits}(u_1) &= \mathsf{maxbits}(p_{11} + p_2)
\end{align}

In order to obtain the maximum value of $p_{11}$, we define $p_{11} := \frac{p_1}{2^\ell}$. Since the maximum value of $p_1$ was $2^{2\ell+2}-2^{\ell+3}+4$, then the maximum value of $p_{11}$ is $2^{\ell+2}-8$. For $p_2$, the maximum value was $6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6$, and thus:

\begin{align}
\mathsf{maxbits}(u_1) &= log_2(\underbrace{2^{\ell+2}-8}_{p_{11}} + \underbrace{6\cdot 2^{2\ell} - 12 \cdot 2^\ell + 6}_{p_2}) \\
&= \log_2(6\cdot 2^{2\ell} - 8 \cdot 2^\ell - 2) \\
\end{align}
which is $2\ell + 3$ bits.

Thus far we have the following constraints
> 2. Composition of $p_{10}$ and $p_{11}$ result in $p_1$
> 3. Range check $p_{11} \in [0, 2^{\ell + 2})$
> 4. Range check $p_{10} \in [0, 2^{\ell})$

For the next step we would like to constrain $u_0$ and $u_1$ to zero.  Unfortunately, we are not able to do this!

As defined $u_0$ will may not be zero, since it contains $v_0$.  Similarly, the highest $\ell + 3$ bits of $p - r$ would wrap to zero $\mod 2^t$; however, when placed into the smaller $2\ell + 3$ bit $u_1$ in the native field, this wrapping does not happen.  Thus, $u_1$'s $\ell + 3$ highest bits may be nonzero.

## Computing carry witnesses values $v_0$ and $v_1$

Thus, instead of constraining $u_0$ and $u_1$ to zero, there must be satisfying witness $v_0$ and $v_1$ such that the following constraints hold.
> 5. There exists $v_0$ such that $u_0 = v_0 \cdot 2^{2\ell}$
> 6. There exists $v_1$ such that $u_1 + v_0 = v_1 \cdot 2^{\ell}$

where $v_0$ is the result of adding the highest bit of $p_0$ and any possible carry bit from the operation of $u_0$, and $v_1$ corresponds to the highest $\ell + 3$ bits of $u_1$.how this proves

Remember we only need to prove the first $3\ell$ bits of $p - r$ are zero, since everything is $\mod 2^t$ and  $t = 3\ell$.  It may not be clear how this prefix witness approach, proves the $3\ell$ bits are indeed zero because within $u_0$ and $u_1$ there are bits that are nonzero.  The key observation is that these bits are too high for $\mod 2^t$.

By making the prefix argument with $v_0$ and $v_1$ we are proving that $u_0$ is something prefixed with $2\ell$ zeros and that $u_1$ is something prefixed with $\ell$ zeros.  Any nonzero bits after $3\ell$ do not matter, since everything is $\mod 2^t$.

All that remains is to range check $v_0$ and $v_1$
> 7. Range check $v_0 \in [0, 3]$
> 8. Range check $v_1 =\in [0, 2^{\ell + 3})$

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

This gives us equality $\mod 2^tn$ as long as the divisors are coprime.  That is, as long as $\mathsf{gcd}(2^t, n) = 1$.  Since the native modulus $n$ is prime, this is true.

Thus, to perform this check is simple.  We compute

\begin{aligned}
a' &= a \mod n \\
b' &= b \mod n \\
q' &= q \mod n \\
f' &= f \mod n \\
r' &= r \mod n
\end{aligned}

and then constrain

$$
a'b' - q'f' - r' = 0 \mod n.
$$

Easy peasy, lemon squeezy!

## Range check $q$ so that $qf + r < 2^tn$

> The reason this range constraint is needed is that the CRT allows us to verify the desired equality $ab = qf + r$ as integers only when both side of the equation are smaller than $2^tn$.

In our specific case, $t=264$, $n < 2^{255}$ and $f < 2^{256}$. Then, we can create a constraint for our case that is sufficient to check the above. Concretely, if $q$ was such that $q < 2^{256}$ (even if potentially larger than $f$), we can see that the above claim holds. 

If $q < 2^{256}$, and since $f < 2^{256}$ as well, then the main check becomes:

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

Note that the above condition holds by far, 

>Value $r < f$, so we can check
>
>\begin{aligned}
>qf + r < qf + f - 1 < qf + f = f(q + 1) &< >2^tn \\
>q &< 2^t\frac{n}{f} - 1.
>
>However, maybe we should just check
>
>$$
>q < f
>$$
>
>and 
>
>$$
>f < 2^t
>$$
>
>instead.


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