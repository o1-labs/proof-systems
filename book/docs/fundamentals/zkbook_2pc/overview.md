# Two Party Computation

This section introduces cryptographic primitives and optimizations of two-party
computation protocols based on Garbled Circuit (GC) and Oblivious Transfer (OT).

More specifically, this section will cover the following contents.

- **Garbled Circuit**
  - Including the Free-XOR, Point-and-Permute, Row-Reduction and Half-Gate
    optimizations.

- **Oblivious Transfer**
  - Including base OT and OT extension. Note that we focus on maliciously secure
    OT protocols. The overhead is comparable to protocols with semi-honest
    security.

- **Two-Party Computation Protocol**
  - This is the well-known Yao's 2PC protocol based on GC and OT.
