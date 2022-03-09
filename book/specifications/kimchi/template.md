# Kimchi

* This document specifies *kimchi*, a zero-knowledge proof system that's a variant of PLONK.
* This document does not specify how circuits are created, or executed. Only how to convert a circuit and its execution into a proof.

## Overview

There's three main algorithms to kimchi:

* [Setup](#constraint-system-creation): takes a circuit and produces a prover index, and a verifier index.
* [Proof creation](#proof-creation): takes the prover index, and the execution trace of the circuit to produce a proof.
* [Proof verification](#proof-verification): takes the verifier index and a proof to verify.

As part of these algorithms, a number of tables are created (and then converted into polynomials) to create a proof.

**Gates**. A circuit is described by a series of gates, that we list in a table. 
The columns of the tables list the gates, while the rows are the length of the circuit. 
For each row, only a single gate can take a value $1$ while all other gates take the value $0$.

|  row  | Generic | Poseidon | CompleteAdd | VarBaseMul | EndoMul | EndoMulScalar | ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal |
| :---: | :-----: | :------: | :---------: | :--------: | :-----: | :-----------: | :-----: | :-----: | :-----: | :---------: |
|   0   |    1    |    0     |      0      |     0      |    0    |       0       |    0    |    0    |    0    |      0      |
|   1   |    0    |    1     |      0      |     0      |    0    |       0       |    0    |    0    |    0    |      0      |

**Coefficients**. The coefficient table has 15 columns, and is used to tweak the gates. 
Currently, only the [Generic](#double-generic-gate) and the [Poseidon](#poseidon) gates use it (refer to their own sections to see how). 
All other gates set their values to $0$.

|  row  |   0   |   1   |   2   |   3   |   4   |   5   |   6   |   7   |   8   |   9   |  10   |  11   |  12   |  13   |  14   |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
|   0   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |

**Registers (or Witness)**. Registers are also defined at every row, and are split into two types: the *IO registers* from $0$ to $6$ usually contain input or output of the gates (note that a gate can output a value on the next row as well). 
I/O registers can be wired to each other (they'll be forced to have the same value), no matter what row they're on (for example, the register at `row:0, col:4` can be wired to the register at `row:80, col:6`). 
The rest of the registers, $7$ through $14$, are called *advice registers* as they can store values that useful only for the row's active gate. 
Think of them as intermediary or temporary values needed in the computation when the prover executes a circuit.

|  row  |   0   |   1   |   2   |   3   |   4   |   5   |   6   |   7   |   8   |   9   |  10   |  11   |  12   |  13   |  14   |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
|   0   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |   /   |


**Wiring (or Permutation)**. For gates to take output of other gates, we use a wiring table to wire registers together. 
It is defined at every row, but only for the first $7$ registers. 
Each cell specifies a `(row, column)` tuple that it should be wired to. 
Note that if three or more registered are wired together, they must form a cycle. 
For example, if register `(0, 4)` is wired to both registers `(80, 6)` and `(90, 0)` then you would have the following table:

|  row  |    0    |   1   |   2   |   3   |    4     |   5   |    6     |
| :---: | :-----: | :---: | :---: | :---: | :------: | :---: | :------: |
|   0   |   0,0   |  0,1  |  0,2  |  0,3  | **80,6** |  0,5  |   0,6    |
|  ...  |         |       |       |       |          |       |          |
|  80   |  80,0   | 80,1  | 80,2  | 80,3  |   80,4   | 80,5  | **90,0** |
|  ...  |         |       |       |       |          |       |          |
|  90   | **0,4** | 90,1  | 90,2  | 90,3  |   90,4   | 90,5  |   90,6   |

**Wiring (Permutation) trace**. You can think of the permutation trace as an extra register that is used to enforce the wiring specified in the wiring table. 
It is a single column that applies on all the rows as well, which the prover computes as part of a proof.

|  row  |  pt   |
| :---: | :---: |
|   0   |   /   |

**Lookup**: TODO

This specification does not document how to create a circuit, we assume that the following gates are created prior to calling the [setup]() function:

* gates
* coefficients
* wiring (permutation)
* TODO: lookup

To create a proof, the prover will execute the circuit and record an execution trace using the following tables:

* registers
* wiring (permutation) trace
* TODO: lookup

## Dependencies

### Polynomial Commitments

Refer to the [specification on polynomial commitments](./poly-commitment.md). 
We make use of the following functions from that specification:

- `PolyCom.non_hiding_commit(poly) -> PolyCom::NonHidingCommitment`
- `PolyCom.commit(poly) -> PolyCom::HidingCommitment`
- `PolyCom.evaluation_proof(poly, commitment, point) -> EvaluationProof`
- `PolyCom.verify(commitment, point, evaluation, evaluation_proof) -> bool`

### Poseidon hash function

Refer to the [specification on Poseidon](./poseidon.md). 
We make use of the following functions from that specification:

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

{sections.permutation}

### Lookup

{sections.lookup}

### Gates

#### Double Generic Gate

{sections.generic}

#### Poseidon

{sections.poseidon}

#### Chacha 

{sections.chacha}

#### Elliptic Curve Addition

{sections.complete_add}

#### Endo Scalar

{sections.endomul_scalar}

#### Endo Scalar Multiplication

{sections.endosclmul}

#### Scalar Multiplication 

{sections.varbasemul}

## Constraint System Creation

{sections.constraint_system}

## Prover and Verifier Index Creation

{sections.indexes}

## Proof Data Structure

A proof consists of:

* TKTK

## Proof Creation

{sections.prover}

## Proof Verification

{sections.verifier}
