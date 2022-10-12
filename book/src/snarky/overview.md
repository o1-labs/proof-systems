# Snarky

Snarky is a frontend to the [kimchi proof system](../kimchi/overview.md).

It allows users to write circuits that can be proven using kimchi.

This part of the Mina book documents both how to use snarky, and how its internals work.

```admonish
Snarky was originally an OCaml library. It also is known as a typescript library: SnarkyJS. 
This documentation talks about the Rust implementation, which one can refer to as snarky-rs (but we will just say snarky from now on).
```

## High-level design

Snarky is divided into two parts:

* **Circuit-generation**: which is also called the setup or compilation phase. It is when snarky turn code written using its library, to a circuit that kimchi can understand. This can later be used by kimchi to produce prover and verifier keys.
* **Witness-generation**: which is also called the proving, or runtime phase. It is when snarky executes the written program and records its state at various point in time to create an execution trace of the program (which we call witness here). This can later be used by kimchi, with a proving key, to produce a zero-knowledge proof.

A snarky program is constructed using functions exposed by the library. 
The API of snarky that one can use to design circuits can be split in three categories:

* creation of snarky variables (via `compute()`)
* creation of constraints (via `assert` type-functions)
* manipulation of snarky variables (which can sometimes create constraints)

Snarky itself is divided into three parts:

* [The high-level API](./api.md) that you can find in `api.rs` and `traits.rs`
* [The snarky wrapper](./snarky-wrapper.md), which contains the logic for creating user variables and composed types (see the section on [Snarky vars](./vars.md#snarky-vars)).
* [The kimchi backend](./kimchi-backend.md), which contains the logic for constructing the circuit as well as the witness.
