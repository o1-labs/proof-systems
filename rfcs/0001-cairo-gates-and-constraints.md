## Summary
[summary]: #summary

This RFC serves as a documentation for the Cairo-Kimchi proof system (a.k.a. Turshi, an Egyptian pickled veggie) to be
supported by O(1)Labs.


## Motivation
[motivation]: #motivation

The Cairo language developed by StarkWare is a novel high level programming
language for which one can obtain proofs of correct execution based on Starks.
Nonetheless, the StarkWare prover is not available to the public, so the only
way to use this language implies relying on their proof system. 

The idea is to make custom gates to give support for Cairo bytecode instructions (what
Cairo language is compiled to) and provide proofs with a Plonk-like proof system.

This extension should provide us with
* custom Cairo gate for Cairo bytecode instructions
* functions to create gates for each possible Cairo bytecode instruction
* specialized constraints for the logics of each possible Cairo instruction,
  corresponding values of witness and memory contents, that are obtained from the Cairo whitepaper
* permutation argument for checking the consistency of the memory

Possible use-cases:
* Cairo programs running on the blockchain could be proved with Mina
* complementary to snarkyJS

## Preliminaries 
[preliminaries]: #preliminaries
In the last few weeks, the team has discussed several ideas to make this happen. 

One approach to this problem consists of a custom Cairo gate for Kimchi, whose wires correspond to the current and next values of the registers (`pc`, `ap`, `fp`) and its coefficients correspond to Cairo bytecode instructions (16 flags and three offsets). These data, initially represented as a 64-bit word, could be more conveniently represented as 19 field elements (where 16 of them shall be boolean). Then, one could have methods creating gates for each possible Cairo bytecode instruction using the values of the flags, contained in the coefficients field of the Cairo `CircuitGate` (about a dozen of them). 

The problem of this approach is that it is not clear that the 15-wire Kimchi proof system could be the most efficient way to represent this type of constraints. In particular, one would normally want to verify Cairo executions alone, so having interoperability with other types of gates is not so relevant. For that reason, we design Turshi: a Plonk-like proof system designed for Cairo programs.

## Detailed design
[detailed-design]: #detailed-design
In the following, we describe the parts that compose the Turshi proof system for Cairo programs. But first, let us introduce some basic notation for referring to the modules being used.
* `CairoInstruction`: this is a 64-bit word representing a Cairo bytecode instruction ( instructions that need an immediate value will take 2 words instead). 
* `CairoProgram`: this is a set of `CairoInstruction`'s and describes a compiled Cairo program.
* `ClaimedRegisters`: this is a set of three tuples that store the claimed initial and finalization values of the three registers `pc`,`ap`,`fp` upon execution of the `CairoProgram`.
* `ExecutionTrace`: this is a table that contains values obtained upon execution of the `CairoProgram` and describes it. 
* `StateTransition`: this is the set of Cairo constraints that must be satisfied between consecutive states of the `ExecutionTrace`. 
* `CairoMemory`: this is an array that stores the program memory after executing the `CairoProgram`. This means that the first few entries of the `CairoMemory` correspond to the `CairoProgram` itself, and it is followed by values that will make up the witness.

### Setup
Both prover and verifier get as input a compiled `CairoProgram` and a set of claimed register values `ClaimedRegisters` after the execution of the program. These two will make up the so called public input of the proof system. The debug mode of the [Cairo Playground](https://www.cairo-lang.org/playground/) can be used to easily get test cases. If interesting enough, we may consider to integrate the [Cairo compiler](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/cairo/lang/compiler) directly for our tests.

### Prover: 
The first task to be done by the prover is execute-or simulate the execution of-the `CairoProgram` to obtain a correct instantiation of the `CairoMemory`. Together with these private values, the prover generates the `ExecutionTrace` and determines the witness of the relation. In order to prove the correctness of the memory (i.e. single-valued and continuity), it creates four pairs of lists (sorted and unsorted) to perform a permutation argument on them. It commits to the witness of the relation and receives two random field elements $z$ and $\alpha$ from the verifier. The former is used as a random point to evaluate the permutation argument, whereas the latter is used to linearly combine the four arguments securely. 

### Verifier

### Proof
The proof consists of a set of polynomial commitments, a permutation proof, 
