# Proof Systems

This repository contains various zk-SNARK protocol implementations for recursive SNARK composition. [See here for the rust documentation](https://o1-labs.github.io/proof-systems/rustdoc).

Organization:

```
proof-systems/
├── book # the mina book, RFCs, and specifications
├── cairo # a Cairo runner written in rust
├── curves/ # our curves (for now just the pasta curves)
├── groupmap/ # TODO: description
├── kimchi/ # our proof system
├── ocaml/ # ocaml bindings generator tool
├── oracle/ # implementation of the poseidon hash function
├── poly-commitment/ # polynomial commitment code
├── signer/ # implementation of schnorr signature scheme
└── utils/ # collection of useful functions and traits
```
