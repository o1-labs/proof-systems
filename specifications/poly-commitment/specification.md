---
weight: 3
bookFlatSection: false
title: "Polynomial Commitment"
summary: "This document specifies the Polynomial Commitment variant of PLONK."
---

# Polynomial Commitment

Our polynomial commitment scheme is a bootleproof-type of commitment scheme, which is a mix of:

* The polynomial commitment scheme described in appendix A.1 of the [PCD paper](https://eprint.iacr.org/2020/1618).
* The zero-knowledge opening described in section 3.1 of the [HALO paper](https://eprint.iacr.org/2019/1021).

The first use case is to commit to a polynomial (usually a hiding commitment, not revealing the polynomial itself), and later produce evaluations accompanied with proofs.

Several evaluation proofs of different polynomials and/or different evaluations can be aggregated into a single proof, and several proofs can be batch verified (which is faster than verifying each proof one by one).

Another application, useful in recursive zksnarks, is to verify that you know a polynomial that was committed.

## URS

The common parameters used by provers and verifiers are called **Uniform Reference String (URS)**. 

\{\{< hint info >}}
The "uniform" part means that they were generated from random numbers; specificaly, it does not need a trusted setup like in other protocols.
\{\{< /hint >}}

A URS contains:

* a generator 

In Rust, it is represented as such:

{ sections.srs }

## Commit

{ sections.commit}

### Commit without hiding

### Commit hiding

### Commit with an upperbound

### Commit a polynomial that is too large

## Evaluation Proof

## Aggregate proofs

### Same polynomial but different evaluations

### Same evaluation but different polynomials

### Both

## Verification

### Single verification

### Batch verification

### Verification of bounded polynomial

### Verification of split polynomial

## Proof of correct polynomial commitment

TOOD: find a better name
