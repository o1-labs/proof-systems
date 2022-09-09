# RFC: Foreign Field Addition

This document is meant to explain the foreign field addition gate in Kimchi.

## Overview

The goal of this gate is to perform the following operation between a left $a$ and a right $b$ input, to obtain a result $r$
$$a + b = r \mod f$$
where $a,b,r\in\mathbb{F}_f$ belong to the foreign field of modulus $f$ and we work over a native field $\mathbb{F}_n$ with modulus $n$. 

If $f<n$ then we can easily perform the above computation. But in this gate we are interested in the contrary case in which $f>n$. In order to deal with this, we will divide foreign field elements into limbs that fit in our native field. We want to be compatible with the foreign field multiplication gate, and thus the parameters we will be using are the following:

- 3 limbs of 88 bits each (for a total of 264 bits)
- $2^{264} > f$
- our foreign field will have 256-bit length
- our native field has 255-bit length

### Splitting the addition

Let's take a closer look at what we have, if we split our variables in limbs (using little endian)

```text
bits  0..............87|88...........175|176...........263

a  =  (-------a0-------|-------a1-------|-------a2-------)
+ 
b  =  (-------b0-------|-------b1-------|-------b2-------)
=
r  =  (-------r0-------|-------r1-------|-------r2-------)  mod(f)
```
We will perform the addition in 3 steps, one per limb. Now, when we split long additions in this way, we must be careful with carry bits between limbs. Also, even if $a$ and $b$ are foreign field elements, it could be the case that $a+b$ is already larger than the modulus (such addition could be at most $2f-2$), and thus we will have to consider the more general case. That is,
$$ a + b = q \cdot f + r \mod 2^{264}$$
with a field overflow term $x$ that will be either $0$ or $1$. Looking at this in limb form, we have:

```text
bits  0..............87|88...........175|176...........263

a  =  (-------a0-------|-------a1-------|-------a2-------)
+ 
b  =  (-------b0-------|-------b1-------|-------b2-------)
=
o  =  0 | 1
·
f  =  (-------f0-------|-------f1-------|-------f2-------)
+
r  =  (-------r0-------|-------r1-------|-------r2-------)
```

First, if $a+b$ was larger than $f$, then we will have a field overflow (represented by $o = 1$) and we will have to subtract $f$ from the sum $s = a+b$ to obtain $r$. The fact that we introduce this subtraction operation means that the limbs could have a carry bit, but also a borrow. Meaning, these flags can be anything in $\{-1, 0, 1\}$. Next we see more clearly how this works. 

In order to perform this operation in parts, we first take a look at the least significant limb, which is the easiest part. This means, we want to know how to compute $r_0$. First, if the addition of the bits in $a_0$ and $b_0$ produce a carry bit that should propagate to the second limb. That means one has to subtract $2^{88}$ from $s_0 = a_0 + b_0$, add 1 to $s_1 = a_1 + b_1$ and set the low carry bit $c_0$ to 1 (otherwise it is zero). take into account the least significant limb of the modulus, $f_0$. It is also possible that  In that case, the carry bit would have a value of $2^{88}$, meaning a $1$ bit followed by $\ell=88$ zeros. Altogether, that means:

$$a_0 + b_0 = x \cdot f_0 + r_0 + c_0 \cdot 2^{88}$$

Or put in another way, this is equivalent to saying that $a_0 + b_0 - x \cdot f_0 - r_0$ is a multiple of $2^{88}$ (or, the existence of the carry coefficient $c_0$). 

This kind of equation needs an additional check that the carry coefficient is a binary value. We will use this idea for the remaining limbs as well.

Looking at the second limb, we first need to observe that the addition of $a_1$ and $b_1$ can, not only produce a carry bit $c_1$, but they may need to take into account the carry bit from the first limb; $c_0$. Similarly to the above, 

$$a_1 + b_1 = x \cdot f_1 + r_1 + c_1 \cdot 2^{88} - c_0$$

Note that in this case, the carry coefficient from the least significant limb is not multiplied by $2^{88}$, but instead is used as is, since it occupies the least significant position of the second limb. Here, the second carry bit $c_1$ is the one being followed by $88$ zeros. Again, we will have to check that $c_1$ is a bit.

Finally, for the third limb, we obtain a similar equation. But in this case, we do not have to take into account $c_0$ anymore, since it was already considered within $c_1$. Again, the most significant carry bit $c_2$ should be a bit. 

$$a_2 + b_2 = x \cdot f_2 + r_2 + c_2 \cdot 2^{88} - c_1$$

Graphically, this is what is happening:

```text
bits  0..............87|88...........175|176...........263
                       
a  =  (-------a0-------|-------a1-------|-------a2-------)
+                      
b  =  (-------b0-------|-------b1-------|-------b2-------)
                       >                >                >
=                     c_0              c_1              c_2  
x  =  0 | 1           
·
f  =  (-------f0-------|-------f1-------|-------f2-------)
+
r  =  (-------r0-------|-------r1-------|-------r2-------)
```

### Upper bound check

Last but not least, we should perform some range checks to make sure that the result $r$ is contained in $\mathbb{F}_f$. Ideally, we would like to reuse some gates that we already have. In particular, we can perform range checks for $0\leq X <2^{3\ell}=2^{3\cdot 88}$. But we want to check that $0\leq r<f$. The way we can tweak this gate to do behave as we want, is the following. First, the above inequation is equivalent to saying that $-f \leq r - f < 0$. Then we add $2^{264}$ on both sides to obtain $2^{264} - f \leq r - f + 2^{264} < 2^{264}$. Let $g$ be $2^{264}-f$ (a publicly computable value) and denote by $g_0, g_1, g_2$ its limbs. Then we have:

$$g\leq r + g = u < 2^{264}$$

which is very similar to a foreign field addition, but simpler: in this case, since the sum $u$ should be strictly less than $2^{264}$ (and $\geq 0$), then there must be no exceeding terms. Meaning, the above field overflow term should always be zero. Nonetheless, there could be intermediate limb carry bits $k_0$ and $k_1$. Observe that, because the sum is $<2^{264}$, then the carry bit for the most significant limb should always be zero $k_2 = 0$, so we do not use it. 


```text
bits  0..............87|88...........175|176...........263
                       
r  =  (-------r0-------|-------r1-------|-------r2-------)
+                      
g  =  (-------g0-------|-------g1-------|-------g2-------)
                       >                >               
=                     k_0              k_1                

u  =  (-------u0-------|-------u1-------|-------u2-------)
```

Following the steps above, and representing this equation in limb form, we have:

\begin{eqnarray}
u_0 &=& r_0 + g_0 - k_0 \cdot 2^{88} \\
u_1 &=& r_1 + g_1 - k_1 \cdot 2^{88} + k_0\\
u_2 &=& r_2 + g_2 + k_1\\
\end{eqnarray}

Finally, we perform a range check on the sum $u$, and we would know that $r < f$. 

But now we also have to check that $0\leq r$ or, equivalently, $g\leq u$. Isn't the first check trivial because $r$ is a field element?


### Subtractions

Mathematically speaking, a subtraction within a field is no more than an addition over that field. Negative elements are not different from "positive" elements in finite fields (or in any modular arithmetic). To give a general example, the element $-e$ within a field $\mathbb{F}_m$ of order $m$ and $e<m$ is nothing but $m - e$. Nonetheless, for arbitrarily sized elements (not just those smaller than the modulus), the actual field element could be any $c \cdot m - e$, for any multiple $c \cdot m$ of the modulus. Thus, representing negative elements directly as "absolute" field elements may incur in additional computations involving multiplications and thus would result in a less efficient mechanism. 

Alternatively, one can store negative values $-e$ as a negative sign followed by the absolute value $e$. Doing so will affect the way we address foreign field additions in the case that we had $a - b$ or $b - a$ (note that $- a - b$ is just the negation of $a + b$, and nothing changes at the gate level). Specifically, the carries between limbs may not just be bits ($0$ or $1$), but they could also be $-1$. This change only affects the values of $c_0, c_1, c_2$. 

For the second part of the gate, meaning the sum for the range check, the carry bits will remain unchanged. The reason behind this is the fact that $g > 0$ because $2^{264} > f$, and $r$ will be "positive" as well. That means, this sum follows the usual positive-addition carry structure. 

## Gadget

The foreign field gadget will be composed by 4 sets of `RangeCheck` gadgets for witnesses $a, b, r, s$ accounting for 16 rows in total; followed by one row with `ForeignFieldAdd` gate type; and a final `Zero` row. A total of 18 rows with 15 columns in Kimchi.

| Row(s) | Gate type(s)        | Witness |
| ------ | ------------------- | ------- |
| 0-3    | `multi-range-check` | $a$     |
| 4-7    | `multi-range-check` | $b$     |
| 8-11   | `multi-range-check` | $r$     |
| 12-15  | `multi-range-check` | $s$     |
| 16     | `ForeignFieldAdd`   |         |
| 17     | `Zero`              |         |


### Layout

For this gate, we need to perform 4 range checks to assert that the limbs of $a, b, r, s$ have a correct size, meaning they fit in $2^{88}$ (and thus, range-checking $a, b, r, s$ for $2^{264}$). Because each of these elements is split into 3 limbs, we will have to use 3 copy constraints between the `RangeCheck` gates and the `ForeignFieldAdd` rows (per element). That amounts to 12 copy constraints. Recalling that Kimchi only allows for the first 7 columns of each row to host a copy constraint, we necessarily have to use 2 rows for the actual addition gate. The layout of these two rows is the following:

|            | Curr              | Next         |
| ---------- | ----------------- | ------------ |
| **Column** | `ForeignFieldAdd` | `Zero`       |
| 0          | $a_0$ (copy)      | $r_0$ (copy) |
| 1          | $a_1$ (copy)      | $r_1$ (copy) |
| 2          | $a_2$ (copy)      | $r_2$ (copy) |
| 3          | $b_0$ (copy)      | $u_0$ (copy) |
| 4          | $b_1$ (copy)      | $u_1$ (copy) |
| 5          | $b_2$ (copy)      | $u_2$ (copy) |
| 6          | $x$               |
| 7          | $c_0$             |
| 8          | $c_1$             |
| 9          | $k_0$             |
| 10         | $k_1$             |
| 11         |                   |
| 12         |                   |
| 13         |                   |
| 14         |                   |

### Constraints

So far, we have pointed out the following sets of constraints:

#### Main addition

- $2^{88} \cdot c_0 = a_0 + b_0 - x \cdot f_0$
- $2^{88} \cdot c_1 = a_1 + b_1 - x \cdot f_1 + c_0$
- $2^{88} \cdot c_2 = a_2 + b_2 - x \cdot f_2 + c_1$

#### Field check

- $u_0 = r_0 + g_0 - k_0 \cdot 2^{88}$
- $u_1 = r_1 + g_1 - k_1 \cdot 2^{88} + k_0$
- $u_2 = r_2 + g_2 + k_1$

#### Carry checks

- $0 = c_0 \cdot (c_0 + 1) \cdot (c_0 - 1)$
- $0 = c_1 \cdot (c_0 + 1) \cdot (c_1 - 1)$
- $0 = c_2 \cdot (c_0 + 1) \cdot (c_2 - 1)$
- $0 = k_0 \cdot (k_0 - 1)$ 
- $0 = k_1 \cdot (k_1 - 1)$

## Optimizations

When we use this gate as part of a larger chained gadget, we should optimize the number of range check rows
to avoid redundant checks. In particular, if the result of an addition becomes one input of another addition, there is no need to check twice that the limbs of that term have the right length.

