# Summary

- [Introduction](./introduction.md)

# Foundations

- [Terminology](./fundamentals/zkbook_foundations.md)
- [Groups](./fundamentals/zkbook_groups.md)
- [Rings](./fundamentals/zkbook_rings.md)
- [Fields](./fundamentals/zkbook.md)
- [Polynomials](./fundamentals/zkbook_polynomials.md)
  - [Multiplying polynomials](./fundamentals/zkbook_multiplying_polynomials.md)
  - [Fast Fourier transform](./fundamentals/zkbook_fft.md)

# Cryptographic tools

- [Commitments](./fundamentals/zkbook_commitment.md)
- [Polynomial commitments](./plonk/polynomial_commitments.md)
  - [Inner product argument](./plonk/inner_product.md)
  - [Different functionnalities](./plonk/inner_product_api.md)
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
- [Lagrange basis in multiplicative subgroups](./plonk/lagrange.md)
- [Non-interaction with fiat-shamir](./plonk/fiat_shamir.md)
- [Plookup](./plonk/plookup.md)
- [Maller's optimization](./plonk/maller.md)

# Kimchi

- [Overview](./kimchi/overview.md)
  - [Arguments](./kimchi/arguments.md)
    - [Custom gates](./kimchi/gates.md)
    - [Permutation](./kimchi/permut.md)
    - [Lookup](./kimchi/lookup.md)

# Snarky

- [Overview](./snarky/overview.md)
- [API](./snarky/api.md)
- [snarky wrapper](./snarky/snarky-wrapper.md)
- [Kimchi backend](./snarky/kimchi-backend.md)
- [Vars](./snarky/vars.md)
- [Booleans](./snarky/booleans.md)
- [Circuit generation](./snarky/circuit-generation.md)
- [Witness generation](./snarky/witness-generation.md)

# Pickles & Inductive Proof Systems

- [Overview](./fundamentals/zkbook_ips.md)
- [Accumulation](./pickles/accumulation.md)
- [Deferred Computation](./pickles/deferred.md)
- [Passthough & Me-Only](./pickles/passthrough.md)

# RFCs

- [RFC 0: Alternative zero-knowledge](./plonk/zkpm.md)
- [RFC 1: Final check](./plonk/final_check.md)
- [RFC 2: Maller's optimization for kimchi](./plonk/maller_15.md)
- [RFC 3: Plookup integration in kimchi](./rfcs/3-lookup.md)
- [RFC 4: Extended lookup tables](./rfcs/extended-lookup-tables.md)
- [RFC 5: Foreign Field Addition](./rfcs/foreign_field_add.md)
- [RFC 6: Foreign Field Multiplication](./rfcs/foreign_field_mul.md)
- [RFC 7: Keccak](./rfcs/keccak.md)
  
# Specifications

- [Poseidon hash](./specs/poseidon.md)
- [Polynomial commitment](./specs/poly-commitment.md)
- [Pasta curves](./specs/pasta.md)
- [Kimchi](./specs/kimchi.md)
- [Universal Reference String (URS)](./specs/urs.md)
- [Pickles](./specs/pickles.md)
- [Consensus](./specs/consensus.md)
