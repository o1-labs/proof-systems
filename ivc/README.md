## IVC circuit for folding over the same curve

This crate implements the circuit that can be used with the folding crate to
achieve incrementally verifiable computation.
The particularity is that it doesn't require a cycle of curve.
It is aimed to be used with the MSM circuit.

### Structure

Integration tests with different circuits are available in the subdirectory
`tests`.
They can be executed by running `cargo nextest run --release` at the level of
this file.
