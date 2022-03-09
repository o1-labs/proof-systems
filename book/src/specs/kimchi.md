# Kimchi

This document specifies the kimchi variant of PLONK.

## Overview

TKTK

## Dependencies

### Polynomial Commitments

Refer to the [specification on polynomial commitments](./poly-commitment.md). We make use of the following functions from that specification:

- `PolyCom.non_hiding_commit(poly) -> PolyCom::NonHidingCommitment`
- `PolyCom.commit(poly) -> PolyCom::HidingCommitment`
- `PolyCom.evaluation_proof(poly, commitment, point) -> EvaluationProof`
- `PolyCom.verify(commitment, point, evaluation, evaluation_proof) -> bool`

### Poseidon hash function

Refer to the [specification on Poseidon](./poseidon.md). We make use of the following functions from that specification:

- `Poseidon.init(params) -> FqSponge`
- `Poseidon.update(field_elem)`
- `Poseidon.finalize() -> FieldElem`

specify the following functions on top:

- `Poseidon.produce_challenge()` (TODO: uses the endomorphism)
- `Poseidon.to_fr_sponge() -> state_of_fq_sponge_before_eval, FrSponge`

With the current parameters:

* `SPONGE_BOX = 7`
* TODO: round constants?
* TODO: MDS?

### Pasta

Kimchi is made to work on cycles of curves, so the protocol switch between two fields Fq and Fr, where Fq represents the base field and Fr represents the scalar field.

See the [Pasta curves specification](./pasta.md).

## Constraints

TODO: use expr to define the index columns?

### Permutation



### Lookup



### Gates

#### Double Generic Gate

The double generic gate contains two generic gates.

A generic gate is simply the 2-fan in gate specified in the
vanilla PLONK protocol that allows us to do operations like:

* addition of two registers (into an output register)
* or multiplication of two registers
* equality of a register with a constant

More generally, the generic gate controls the coefficients $c_i$ in the equation:

$$c_0 \cdot l + c_1 \cdot r + c_2 \cdot o + c_3 \cdot (l \times r) + c_4$$

The layout of the gate is the following:

|  0 |  1 |  2 |  3 |  4 |  5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|:--:|:--:|:--:|:--:|:--:|:--:|:-:|:-:|:-:|:-:|:--:|:--:|:--:|:--:|:--:|
| l1 | r1 | o1 | l2 | r2 | o2 |   |   |   |   |    |    |    |    |    |

where l1, r1, and o1 (resp. l2, r2, o2)
are the left, right, and output registers
of the first (resp. second) generic gate.

The selectors are stored in the coefficient table as:

|  0 |  1 |  2 |  3 |  4 |  5 | 6  |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| l1 | r1 | o1 | m1 | c1 | l2 | r2 | o2 | m2 | c2 |    |    |    |    |    |

with m1 (resp. m2) the mul selector for the first (resp. second) gate,
and c1 (resp. c2) the constant selector for the first (resp. second) gate.

The constraints:

* $w_0 \cdot c_0 + w_1 \cdot c_1 + w_2 \cdot c_2 + w_0 \cdot w_1 \cdot c_3 + c_4$
* $w_3 \cdot c_5 + w_4 \cdot c_6 + w_5 \cdot c_7 + w_3 w_4 c_8 + c_9$

where the $c_i$ are the [coefficients]().


#### Poseidon

The poseidon gate encodes 5 rounds of the poseidon permutation.
A state is represents by 3 field elements. For example,
the first state is represented by `(s0, s0, s0)`,
and the next state, after permutation, is represented by `(s1, s1, s1)`.

Below is how we store each state in the register table:

|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| s0 | s0 | s0 | s4 | s4 | s4 | s1 | s1 | s1 | s2 | s2 | s2 | s3 | s3 | s3 |
| s5 | s5 | s5 |    |    |    |    |    |    |    |    |    |    |    |    |

The last state is stored on the next row. This last state is either used:

* with another Poseidon gate on that next row, representing the next 5 rounds.
* or with a Zero gate, and a permutation to use the output elsewhere in the circuit.
* or with another gate expecting an input of 3 field elements in its first registers.

```admonish
As some of the poseidon hash variants might not use $5k$ rounds (for some $k$),
the result of the 4-th round is stored directly after the initial state.
This makes that state accessible to the permutation.
```

We define $M_{r, c}$ as the MDS matrix at row $r$ and column $c$.

We define the S-box operation as $w^S$ for $S$ the `SPONGE_BOX` constant.

We store the 15 round constants $r_i$ required for the 5 rounds (3 per round) in the coefficient table:

|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| r0 | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | r11 | r12 | r13 | r14 |

The initial state, stored in the first three registers, are not constrained.
The following 4 states (of 3 field elements), including 1 in the next row,
are constrained to represent the 5 rounds of permutation.
Each of the associated 15 registers is associated to a constraint, calculated as:

first round:
* $w_6 - r_0 + (M_{0, 0} w_0^S + M_{0, 1} w_1^S + M_{0, 2} w_2^S)$
* $w_7 - r_1 + (M_{1, 0} w_0^S + M_{1, 1} w_1^S + M_{1, 2} w_2^S)$
* $w_8 - r_2 + (M_{2, 0} w_0^S + M_{2, 1} w_1^S + M_{2, 2} w_2^S)$

second round:
* $w_9 - r_3 + (M_{0, 0} w_6^S + M_{0, 1} w_7^S + M_{0, 2} w_8^S)$
* $w_{10} - r_4 + (M_{1, 0} w_6^S + M_{1, 1} w_7^S + M_{1, 2} w_8^S)$
* $w_{11} - r_5 + (M_{2, 0} w_6^S + M_{2, 1} w_7^S + M_{2, 2} w_8^S)$

third round:
* $w_{12} - r_6 + (M_{0, 0} w_9^S + M_{0, 1} w_{10}^S + M_{0, 2} w_{11}^S)$
* $w_{13} - r_7 + (M_{1, 0} w_9^S + M_{1, 1} w_{10}^S + M_{1, 2} w_{11}^S)$
* $w_{14} - r_8 + (M_{2, 0} w_9^S + M_{2, 1} w_{10}^S + M_{2, 2} w_{11}^S)$

fourth round:
* $w_3 - r_9 + (M_{0, 0} w_{12}^S + M_{0, 1} w_{13}^S + M_{0, 2} w_{14}^S)$
* $w_4 - r_{10} + (M_{1, 0} w_{12}^S + M_{1, 1} w_{13}^S + M_{1, 2} w_{14}^S)$
* $w_5 - r_{11} + (M_{2, 0} w_{12}^S + M_{2, 1} w_{13}^S + M_{2, 2} w_{14}^S)$

fifth round:
* $w_{0, next} - r_{12} + (M_{0, 0} w_3^S + M_{0, 1} w_4^S + M_{0, 2} w_5^S)$
* $w_{1, next} - r_{13} + (M_{1, 0} w_3^S + M_{1, 1} w_4^S + M_{1, 2} w_5^S)$
* $w_{2, next} - r_{14} + (M_{2, 0} w_3^S + M_{2, 1} w_4^S + M_{2, 2} w_5^S)$



#### Chacha 



#### Elliptic Curve Addition



#### Endo Scalar



#### Endo Scalar Multiplication



#### Scalar Multiplication 



## Constraint System Creation



## Prover and Verifier Index Creation



## Proof Data Structure

A proof consists of:

* TKTK

## Proof Creation



## Proof Verification


