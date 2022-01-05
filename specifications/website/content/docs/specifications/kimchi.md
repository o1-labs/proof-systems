---
weight: 3
bookFlatSection: false
title: "Kimchi"
summary: "This document specifies the kimchi variant of PLONK."
---

# Kimchi

**THIS IS WORK-IN-PROGRESS**

This document specifies the kimchi variant of PLONK.

## Overview

The document follows the following structure:

TODO: simply create a ToC no?

1. **Setup**. A one-time setup for the proof system.
2. **Per-circuit setup**. A one-time setup for each circuit that are used in the proof system.
3. **Proof creation**. How to create a proof.
4. **Proof verification**. How to verify a proof.

## Dependencies

### Polynomial Commitments

Refer to the [specification on polynomial commitments](). We make use of the following functions from that specification:

- `PolyCom.non_hiding_commit(poly) -> PolyCom::NonHidingCommitment`
- `PolyCom.commit(poly) -> PolyCom::HidingCommitment`
- `PolyCom.evaluation_proof(poly, commitment, point) -> EvaluationProof`
- `PolyCom.verify(commitment, point, evaluation, evaluation_proof) -> bool`

### Poseidon hash function

Refer to the [specification on Poseidon](). We make use of the following functions from that specification:

- `Poseidon.init(params) -> FqSponge`
- `Poseidon.update(field_elem)`
- `Poseidon.finalize() -> FieldElem`

specify the following functions on top:

- `Poseidon.produce_challenge()` (TODO: uses the endomorphism)
- `Poseidon.to_fr_sponge() -> state_of_fq_sponge_before_eval, FrSponge`

### Pasta

Kimchi is made to work on cycles of curves, so the protocol switch between two fields Fq and Fr, where Fq represents the base field and Fr represents the scalar field.

## Constraints

### Permutation



### Lookup



### Gates

#### Generic Gate



#### Poseidon



#### chacha 

There are four chacha constraint types, corresponding to the four lines in each quarter round.

```
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;
```

or, written without mutation, (and where `+` is mod $2^32$),

```
a'  = a + b ; d' = (d ⊕ a') <<< 16;
c'  = c + d'; b' = (b ⊕ c') <<< 12;
a'' = a' + b'; d'' = (d' ⊕ a') <<< 8;
c'' = c' + d''; b'' = (c'' ⊕ b') <<< 7;
```

We lay each line as two rows.

Each line has the form

```
x += z; y ^= x; y <<<= k
```

or without mutation,

```
x' = x + z; y' = (y ⊕ x') <<< k
```

which we abbreviate as

L(x, x', y, y', z, k)

In general, such a line will be laid out as the two rows


| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|----|----|----|----|----|
| x | y | z | (y^x')_0 | (y^x')_1 | (y^x')_2 | (y^x')_3 | (x+z)_0 | (x+z)_1 | (x+z)_2 | (x+z)_3 | y_0 | y_1 | y_2 | y_3 |
| x' | y' | (x+z)_8 | (y^x')_4 | (y^x')_5 | (y^x')_6 | (y^x')_7 | (x+z)_4 | (x+z)_5 | (x+z)_6 | (x+z)_7 | y_4 | y_5 | y_6 | y_7 |

where A_i indicates the i^th nybble (four-bit chunk) of the value A.

$(x+z)_8$ is special, since we know it is actually at most 1 bit (representing the overflow bit of x + z).

So the first line `L(a, a', d, d', b, 8)` for example becomes the two rows

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|----|----|----|----|----|
| a | d | b | (d^a')_0 | (d^a')_1 | (d^a')_2 | (d^a')_3 | (a+b)_0 | (a+b)_1 | (a+b)_2 | (a+b)_3 | d_0 | d_1 | d_2 | d_3 |
| a' | d' | (a+b)_8 | (d^a')_4 | (d^a')_5 | (d^a')_6 | (d^a')_7 | (a+b)_4 | (a+b)_5 | (a+b)_6 | (a+b)_7 | d_4 | d_5 | d_6 | d_7 |

along with the equations

* $(a+b)_8^2 = (a+b)_8$ (booleanity check)
* $a' = \sum_{i = 0}^7 (2^4)^i (a+b)_i$
* $a + b = 2^32 (a+b)_8 + a'$
* $d = \sum_{i = 0}^7 (2^4)^i d_i$
* $d' = \sum_{i = 0}^7 (2^4)^{(i + 4) mod 8} (a+b)_i$

The $(i + 4) \mod 8$ rotates the nybbles left by 4, which means bit-rotating by $4 \times 4 = 16$ as desired.

The final line is a bit more complicated as we have to rotate by 7, which is not a multiple of 4.
We accomplish this as follows.

Let's say we want to rotate the nybbles $A_0, \cdots, A_7$ left by 7.
First we'll rotate left by 4 to get

$$A_7, A_0, A_1, \cdots, A_6$$

Rename these as
$$B_0, \cdots, B_7$$

We now want to left-rotate each $B_i$ by 3.

Let $b_i$ be the low bit of $B_i$.
Then, the low 3 bits of $B_i$ are
$(B_i - b_i) / 2$.

The result will thus be

* $2^3 b_0 + (B_7 - b_7)/2$
* $2^3 b_1 + (B_0 - b_0)/2$
* $2^3 b_2 + (B_1 - b_1)/2$
* $\cdots$
* $2^3 b_7 + (B_6 - b_6)/2$

or re-writing in terms of our original nybbles $A_i$,

* $2^3 a_7 + (A_6 - a_6)/2$
* $2^3 a_0 + (A_7 - a_7)/2$
* $2^3 a_1 + (A_0 - a_0)/2$
* $2^3 a_2 + (A_1 - a_1)/2$
* $2^3 a_3 + (A_2 - a_2)/2$
* $2^3 a_4 + (A_3 - a_3)/2$
* $2^3 a_5 + (A_4 - a_4)/2$
* $2^3 a_6 + (A_5 - a_5)/2$

For neatness, letting $(x, y, z) = (c', b', d'')$, the first 2 rows for the final line will be:

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|----|----|----|----|----|
| x | y | z | (y^x')_0 | (y^x')_1 | (y^x')_2 | (y^x')_3 | (x+z)_0 | (x+z)_1 | (x+z)_2 | (x+z)_3 | y_0 | y_1 | y_2 | y_3 |
| x' | _ | (x+z)_8 | (y^x')_4 | (y^x')_5 | (y^x')_6 | (y^x')_7 | (x+z)_4 | (x+z)_5 | (x+z)_6 | (x+z)_7 | y_4 | y_5 | y_6 | y_7 |

but then we also need to perform the bit-rotate by 1.

For this we'll add an additional 2 rows. It's probably possible to do it with just 1,
but I think we'd have to change our plookup setup somehow, or maybe expand the number of columns,
or allow access to the previous row.

Let lo(n) be the low bit of the nybble n. The 2 rows will be

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|----|----|----|----|----|
| y' | (y^x')_0 | (y^x')_1 | (y^x')_2 | (y^x')_3 | lo((y^x')_0) | lo((y^x')_1) | lo((y^x')_2) | lo((y^x')_3) |
| _ | (y^x')_4 | (y^x')_5 | (y^x')_6 | (y^x')_7 | lo((y^x')_4) | lo((y^x')_5) | lo((y^x')_6) | lo((y^x')_7) |

On each of them we'll do the plookups

((cols[1] - cols[5])/2, (cols[1] - cols[5])/2, 0) in XOR
((cols[2] - cols[6])/2, (cols[2] - cols[6])/2, 0) in XOR
((cols[3] - cols[7])/2, (cols[3] - cols[7])/2, 0) in XOR
((cols[4] - cols[8])/2, (cols[4] - cols[8])/2, 0) in XOR

which checks that $(y^{x'})_i - lo((y^{x'})_i)$ is a nybble,
which guarantees that the low bit is computed correctly.

There is no need to check nybbleness of (y^x')_i because those will be constrained to
be equal to the copies of those values from previous rows, which have already been
constrained for nybbleness (by the lookup in the XOR table).

And we'll check that y' is the sum of the shifted nybbles.


#### complete_add 



#### endomul_scalar 



#### endosclmul 



#### poseidon 



#### varbasemul 



## constraint system creation (circuit creation)


## ConstraintSystem

1. +3 on gates.len() here to ensure that we have room for the zero-knowledge entries of the permutation polynomial
2. pad the rows: add zero gates to reach the domain size
3. sample the coordinate shifts
4. compute permutation polynomials
4. Gates
  a. compute poseidon constraint polynomials
  b. compute ECC arithmetic constraint polynomials
 c. generic constraint polynomials
 d. chacha
  e. coefficients
 f. poseidon
1. Lookup
  a. get the last entry in each column of each table
  b. pre-compute polynomial and evaluation form for the look up tables
  c. generate the look up selector polynomials if any lookup-based gate is being used in the circuit
1. the result is the constraint system, describing the circuit


## prover and verifier index creation


## Verifier Index

The verifier index is a structure that contains all the information needed to verify a proof.
You can create the verifier index from the prover index, by commiting to a number of polynomials in advance.


## Prover Index

The prover index is a structure that contains all the information needed to
generate the proof.

1. do the lookup stuff


## proof data structure

TKTK

## proof creation

1. add zero-knowledge rows to the execution trace
   (see https://o1-labs.github.io/mina-book/crypto/plonk/zkpm.html)
    - ensure that execution traces are all of size smaller than d1_size - ZK_ROWS
     (TODO: specify d1_size and ZK_ROWS)
    - check that the execution traces are all of the same size
    - pad each execution trace with enough zeros to make them of length d1_size
    - randomize the last three rows of each execution trace
3. compute the public input polynomial as $-p$,
   where $p$ is the polynomial representing the public input as such:
   * $p(\omega^i) = w_0[i]$ for $i \in [[0, l]]$
   * $p(\omega^j) = 0$ for $j \in [[l+1, n]]$

   and $w_0$ is the execution trace of the first register,
   which contains the public input f in the first $l$ rows
4. commit to the execution traces of the 15 registers:
   - interpolate each register $w_i$ into a polynomial
   - commit (with hiding) to each polynomial to obtain $com(w_i)$
5. compute witness polynomials
6. absorb the wire polycommitments into the argument
7. build the lookup stuff
8. sample beta, gamma oracles
9. more lookup stuff
10. compute permutation aggregation polynomial
11. commit to the permutation polynomial z
12. absorb the permutation commitment into the argument
13. query $\alpha$
14. evaluate polynomials over domains
15. compute quotient polynomial
16. divide contributions with vanishing polynomial
19. sample zeta
20. evaluate the polynomials
21. compute and evaluate linearization polynomial


## proof verification


