# zkVM

This document will introduce the different concepts, building blocks and
cryptographic components used to build the O(1) Labs zkVM.
The document should be relatively self-contained and be enough to perform an
audit of the program.

## Background

## Prover

Let's focus first on proving a certain bounded set of instructions, like small
programs. Let's forget folding and Keccak.

What does a proof contain?
The proof has commitments to some polynomials and evaluations at a certain points of these polynomials.

<!-- The polynomials are of degree N where N is the size of the circuit, i.e. the number of steps the -->
Q: degree of the polynomials?
Q: what are these polynomials?

Let's list the different polynomials and the reason of their existence.

### Instructions parts

At each step, the current instruction is fetched from the memory, and it is decoded in its different parts, see [the instruction format](https://max.cs.kzoo.edu/cs230/Resources/MIPS/MachineXL/InstructionFormats.html). This is the role of the interpreter, implemented in [interpreter.rs](./interpreter.rs) <-- TODO: update the link -->

| op


Memory
At the beginning of the program, your memory is going to look like this:
  Addr:     0      4      8     12   ...   4096 (2^12)
  Value:    42     3      3     1           42

At the end of the program your memory is going to look like this:
  Addr:     0      4      8     12   ...   4096 (2^12)
  Value:    42     3      3     1           42

Is the domain size, i.e. the number of instructions, the number of addresses that we commit too for the initial and final memory, i.e. do we touch only d1 size addresses during the execution of the program?
------------ Instruction parts ---------------------
----------------------------------------------------
| Domain       | P_{op} | P_{rs} | ... | P_{funct} | P_{initial_memory_addr} | P_{initial_memory_values} | P_{final_memory_addr} | P_{final_memory_values} |
|--------------|--------|--------|-----|-----------|-------------------------|---------------------------|-----------------------|-------------------------|
| 1            | op_{1} |        | ... | funct_{1} | 0                       |                           | 0                     |                         |
| $\omega$     |        |        | ... |           | 4                       |                           | 4                     |                         |
| $\omega^{2}$ |        |        | ... |           | 8                       |                           | 8                     |                         |
| $\omega^{3}$ |        |        | ... |           | 12                      |                           | 12                    |                         |
| ...          |        |        | ... |           | ...                     |                           | ...                    |                         |
| $\omega^{n}|        |        | ... |           | ...                     |                           | ...                    |                         |
|--------------|--------|--------|-----|-----------|-------------------------|---------------------------|-----------------------|-------------------------|


$P
$op_{i}$, $funct_{i}$, etc. are the evaluations of the polynomials $P_{op},
\cdot$ on $\omega_{i}$, and we have to constraint that it is the decomposition
of the current fetched instruction, i.e.

Q: what does the P_{op}, P_{rs} contain?

$q_{r_type} * P(op, rs, rt, rd, shamt, funct)$
$q_{j_type} * P(op, address)$
$q_{i_type} * P(op, rs, rt, immediate)$

$P_{op}(\omega6{i}) + P_{rs}(\omega6{i}) + P_{rt}(\omega^{i}) + P_{rd}(\omega^{i}) + P_{shamt}(\omega^{i})$
Th

### Instruction selectors

At the number, there are 49 <-- FIXME: this isn't totally true, it should be the
number of actual instructions + "fake" isntructions like syscall_fnctl, etc.

### Initial memory

### Final memory
## Memory and register access

## Compatibility with Ethereum

## Folding

## Keccak
