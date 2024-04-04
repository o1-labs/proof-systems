# Summary

- [Introduction](./introduction.md)

# Foundations

- [Terminology](./fundamentals/zkbook_foundations.md)
- [Groups](./fundamentals/zkbook_groups.md)
- [Rings](./fundamentals/zkbook_rings.md)
- [Fields](./fundamentals/zkbook.md)
- [Polynomials](./fundamentals/zkbook_polynomials.md)
  - [Multiplying Polynomials](./fundamentals/zkbook_multiplying_polynomials.md)
  - [Fast Fourier Transform](./fundamentals/zkbook_fft.md)

# Cryptographic tools

- [Commitments](./fundamentals/zkbook_commitment.md)
- [Polynomial Commitments](./plonk/polynomial_commitments.md)
  - [Inner Product Argument](./plonk/inner_product.md)
  - [Different Functionnalities](./plonk/inner_product_api.md)
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

# Proof systems

- [Overview](./fundamentals/proof_systems.md)
- [zk-SNARKs](./fundamentals/zkbook_plonk.md)
- [Custom constraints](./fundamentals/custom_constraints.md)

# Background on PLONK

- [Overview](./plonk/overview.md)
- [Glossary](./plonk/glossary.md)
- [Domain](./plonk/domain.md)
- [Lagrange Basis in Multiplicative Subgroups](./plonk/lagrange.md)
- [Non-interaction with Fiat-Shamir](./plonk/fiat_shamir.md)
- [Plookup](./plonk/plookup.md)
- [Maller's Optimization](./plonk/maller.md)

# Kimchi

- [Overview](./kimchi/overview.md)
  - [Arguments](./kimchi/arguments.md)
    - [Custom Gates](./kimchi/gates.md)
    - [Permutation](./kimchi/permut.md)
    - [Lookup](./kimchi/lookup.md)

# Pickles & Inductive Proof Systems

- [Overview](./fundamentals/zkbook_ips.md)
- [Accumulation](./pickles/accumulation.md)
- [Deferred Computation](./pickles/deferred.md)
- [Passthough & Me-Only](./pickles/passthrough.md)

# RFCs

- [RFC 0: Alternative Zero-Knowledge](./plonk/zkpm.md)
- [RFC 1: Final Check](./plonk/final_check.md)
- [RFC 2: Maller's Optimization for Kimchi](./plonk/maller_15.md)
- [RFC 3: Plookup Integration in Kimchi](./rfcs/3-lookup.md)
- [RFC 4: Extended Lookup Tables](./rfcs/extended-lookup-tables.md)
- [RFC 5: Foreign Field Addition](./rfcs/foreign_field_add.md)
- [RFC 6: Foreign Field Multiplication](./rfcs/foreign_field_mul.md)
- [RFC 7: Keccak](./rfcs/keccak.md)

# Specifications

- [Poseidon hash](./specs/poseidon.md)
- [Polynomial Commitment](./specs/poly-commitment.md)
- [Pasta Curves](./specs/pasta.md)
- [Kimchi](./specs/kimchi.md)
- [Universal Reference String (URS)](./specs/urs.md)
- [Pickles](./specs/pickles.md)
- [Consensus](./specs/consensus.md)
