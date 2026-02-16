# poly-commitment: implementations of multiple PCS

This library offers implementations of different Polynomial Commitment Scheme
(PCS) that can be used in Polynomial Interactive Oracle Proof (PIOP) like PlonK.

Currently, the following polynomial commitment schemes are implemented:

- [KZG10](./src/kzg.rs)
- [Inner Product Argument](./src/ipa.rs)

The implementations are made initially to be compatible with Kimchi (a Plonk-ish
variant with 15 wires and some custom gates) and to be used in the Mina
protocol. For instance, submodules are created to convert into OCaml to be used
in the Mina protocol codebase.
