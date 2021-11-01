# Proof Systems

This repository contains various zk-SNARK protocol implementations for recursive SNARK composition.

```
proof-systems/
├── circuits/ # the circuit and gate relevant code of PLONK
│   ├── plonk/ # the first version of our PLONK
│   └── kimchi/ # the latest PLONK (TODO: rename to kimchi)
├── curves/ # our curves (for now just the pasta curves)
├── dlog/ # the protocols
│   ├── commitment/ # polynomial commitment code, TODO: move this
│   ├── plonk/ # the first version of our PLONK
│   ├── kimchi/ # the latest PLONK (TODO: rename to kimchi)
│   └── tests/ # common tests, TODO: move this within each protocol
├── groupmap/ # TODO: description
├── ocaml-gen/ # ocaml bindings generator tool
├── oracle/ # implementation of the poseidon hash function
└── utils/ # collection of useful functions and traits
```
