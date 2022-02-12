---
weight: 3
bookFlatSection: false
title: "Polynomial Commitment"
summary: "This document specifies the Polynomial Commitment variant of PLONK."
---

# Polynomial Commitment

Kimchi's polynomial commitment is a mix of HALO2's variant of bulletproof and [other paper] optimization.

The first use case is to commit to a polynomial (usually a hiding commitment, not revealing the polynomial itself), and later produce evaluations accompanied with proofs.

Several evaluation proofs of different polynomials and/or different evaluations can be aggregated into a single proof, and several proofs can be batch verified (which is faster than verifying each proof one by one).

Another application, useful in recursive zksnarks, is to verify that you know a polynomial that was committed.

## URS

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
