# Pickles

Pickles is Mina’s inductive zk-SNARK composition system. It lets you construct
proofs with zk-SNARKs and combine them in flexible ways to deliver incremental
verifiable computation.

---

Pickles uses a pair of amicable curves called [Pasta](./pasta.md) in order to
deliver incremental verifiable computation efficiently.

These curves are referred to as "tick" and "tock" within the Mina source code.

- Tick - Vesta (a.k.a. Step), constraint domain size $2^{18}$ (block and
  transaction proofs)
- Tock - Pallas (a.k.a. Wrap), constraint domain size $2^{17}$ (signatures)

The Tock prover does less (only performs recursive verifications and no other
logic), so it requires fewer constraints and has a smaller domain size.
Internally Pickles refers to Tick and Tock as Step and Wrap, respectively.

Tock is used to prove the verification of a Tick proof and outputs a Tick proof.
Tick is used to prove the verification of a Tock proof and outputs a Tock proof.
In other words,

- $\mathtt{Prove}_{tock}(\mathtt{Verify}(Tick)) = Tick_{proof}$
- $\mathtt{Prove}_{tick}(\mathtt{Verify}(Tock)) = Tock_{proof}$

Both Tick and Tock can verify at most 2 proofs of the opposite kind, though,
theoretically more is possible.

Currently, in Mina we have the following situation.

- Every Tock always wraps 1 Tick proof, such as
- Tick proofs can verify 2 Tock proofs
  - Blockchain SNARK takes previous blockchain SNARK proof and a transaction
    proof
  - Verifying two Tock transaction proofs
