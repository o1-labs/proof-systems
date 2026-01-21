# Summary

- [Introduction](./introduction.md)

# Foundations

- [Terminology](./fundamentals/zkbook_foundations.md)
- [Groups](./fundamentals/zkbook_groups.md)
- [Rings](./fundamentals/zkbook_rings.md)
- [Fields](./fundamentals/zkbook_fields.md)
- [Polynomials](./fundamentals/zkbook_polynomials.md)
  - [Multiplying Polynomials](./fundamentals/zkbook_multiplying_polynomials.md)
  - [Fast Fourier Transform](./fundamentals/zkbook_fft.md)

# Cryptographic Tools

- [Commitments](./fundamentals/zkbook_commitment.md)
- [Polynomial Commitments](./plonk/polynomial_commitments.md)
  - [Inner Product Argument](./plonk/inner_product.md)
  - [Different Functionalities](./plonk/inner_product_api.md)
- [Two Party Computation](./fundamentals/zkbook_2pc/overview.md)
  - [Garbled Circuits](./fundamentals/zkbook_2pc/gc.md)
    - [Basics](./fundamentals/zkbook_2pc/basics.md)
    - [Point and Permute](./fundamentals/zkbook_2pc/pap.md)
    - [Free XOR](./fundamentals/zkbook_2pc/freexor.md)
    - [Row Reduction](./fundamentals/zkbook_2pc/row_red.md)
    - [Half Gate](./fundamentals/zkbook_2pc/halfgate.md)
    - [Full Description](./fundamentals/zkbook_2pc/fulldesc.md)
    - [Fixed-Key-AES Hashes](./fundamentals/zkbook_2pc/fkaes.md)
  - [Oblivious Transfer](./fundamentals/zkbook_2pc/ot.md)
    - [Base OT](./fundamentals/zkbook_2pc/baseot.md)
    - [OT Extension](./fundamentals/zkbook_2pc/ote.md)
  - [Full Protocol](./fundamentals/zkbook_2pc/2pc.md)
- [Proof Systems](./fundamentals/proof_systems.md)
  - [zk-SNARKs](./fundamentals/zkbook_plonk.md)

# Background on PLONK

- [Overview](./plonk/overview.md)
  - [Glossary](./plonk/glossary.md)
- [Domain](./plonk/domain.md)
- [Lagrange Basis in Multiplicative Subgroups](./plonk/lagrange.md)
- [Non-Interactivity via Fiat-Shamir](./plonk/fiat_shamir.md)
- [Plookup](./plonk/plookup.md)
- [Maller's Optimization](./plonk/maller.md)
- [Zero-Column Approach to Zero-Knowledge](./plonk/zkpm.md)

# Kimchi

- [Overview](./kimchi/overview.md)
- [Arguments](./kimchi/arguments.md)
- [Final Check](./kimchi/final_check.md)
- [Maller's Optimization for Kimchi](./kimchi/maller_15.md)
- [Lookup Tables](./kimchi/lookup.md)
  - [Extended Lookup Tables](./kimchi/extended-lookup-tables.md)
- [Custom Constraints](./kimchi/custom_constraints.md)
- [Custom Gates](./kimchi/gates.md)
  - [Foreign Field Addition](./kimchi/foreign_field_add.md)
  - [Foreign Field Multiplication](./kimchi/foreign_field_mul.md)
  - [Keccak](./kimchi/keccak.md)

# Pickles & Inductive Proof Systems

- [Overview](./pickles/overview.md)
- [Inductive Proof Systems](./pickles/zkbook_ips.md)
- [Accumulation](./pickles/accumulation.md)
- [Deferred Computation](./pickles/deferred.md)
- [Technical Diagrams](./pickles/diagrams.md)

# Technical Specifications

- [Poseidon hash](./specs/poseidon.md)
- [Polynomial Commitment](./specs/poly-commitment.md)
- [Pasta Curves](./specs/pasta.md)
- [Kimchi](./specs/kimchi.md)
- [Universal Reference String (URS)](./specs/urs.md)
- [Pickles](./specs/pickles.md)
- [Consensus](./specs/consensus.md)
