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
In the following, we describe the parts that compose the Turshi proof system for Cairo programs. It is divided into two main steps: a witness computation phase, followed by the actual proof phase. The goal of the former is to obtain a valid instantiation of the memory that would make an accepting proof. During the latter, some constraints on the contents of the memory and the registers will be created. A satisfying input should derive an accepting proof.

More specifically, let us introduce some basic notation for referring to the modules being used inside each phase. Take into account that right now the computation of the witness is performed with normal arithmetics for a more natural implementation of the computation. Only later in the constraints phase these will have an equivalent field representation (this is subject to change). This means that in the first phase, there is no field arithmetics going on.

### Witness computation
* `CairoWord`: this is essentially a 64-bit element representing a Cairo bytecode word (some instructions can take 2 words). Plenty of methods to obtain each component of the instruction are implemented, as an analogy to Cairo whitepaper's nomenclature (this is not optimized, some components are computed many times instead of storing them as fields of the struct itself). 
````rust
pub struct CairoWord {
    pub word : u64,
}
````
· `biased_rep()`: returns the biased representation of an input `u16` offset and returns it as `i16`. The operation being performed is $n = -2^{15} + \sum_{i=0..15} b_i \cdot 2^i$. This means for instance that $0$ is represented with `0x8000`.

· `CairoWord::new(word: u64)`: creates a `CairoWord` from a 64bit unsigned integer.

· `CairoWord::off_dst()`: returns the destination offset in biased representation as i16. This is the least significant bits of the 64bit word (0 to 15 positions).

· `CairoWord::off_op0()`: returns the first operand offset in biased representation as i16. This is bits from 16 to 31 of the 64 bit word.

· `CairoWord::off_op1()`: returns the second operand offset in biased representation as i16. This is bits from 32 to 47 of the 64 bit word.

· `CairoWord::flags()`: returns the vector of 16 flags corresponding to the word. This is the most significant 16 bits of the 64 bit word (48 to 63 positions).

· `CairoWord::flag_at()`: returns `i`-th bit-flag as `u64`.

· `CairoWord::f_dst_reg()`: returns bit-flag for destination register as `u64`. This is the 0th flag.

· `CairoWord::f_op0_reg()`: returns bit-flag for first operand register as `u64`. This is the 1st flag.

· `CairoWord::f_op1_reg()`: returns bit-flag for immediate value for second register as `u64`. This is the 2nd flag.

· `CairoWord::f_op1_fp()`: returns bit-flag for frame pointer for second register as `u64`. This is the 3rd flag.

· `CairoWord::f_op1_ap()`: returns bit-flag for allocation pointer for second regsiter as `u64`. This is the 4th flag.

· `CairoWord::f_res_add()`: returns bit-flag for addition operation in right side as `u64`. This is the 5th flag.

· `CairoWord::f_res_mul()`: returns bit-flag for multiplication operation in right side as `u64`. This is the 6th flag.

· `CairoWord::f_pc_abs()`: returns bit-flag for program counter update being absolute jump as `u64`. This is the 7th flag.

· `CairoWord::f_pc_rel()`: returns bit-flag for program counter update being relative jump as `u64`. This is the 8th flag.

· `CairoWord::f_pc_jnz()`: returns bit-flag for program counter update being conditional jump as `u64`. This is the 9th flag.

· `CairoWord::f_ap_add()`: returns bit-flag for allocation counter update being a manual addition as `u64`. This is the 10th flag.

· `CairoWord::f_ap_one()`: returns bit-flag for allocation counter update being a self increment as `u64`. This is the 11th flag.

· `CairoWord::f_opc_call()`: returns bit-flag for operation being a 'call' as `u64`. This is the 12th flag.

· `CairoWord::f_opc_ret()`: returns bit-flag for operation being a 'return' as `u64`. This is the 13th flag.

· `CairoWord::f_opc_aeq()`: returns bit-flag for operation being an 'assert-equal' as `u64`. This is the 14th flag.

· `CairoWord::f15()`: this is the 15th flag. A correct instruction will have this bit to zero.

· `CairoWord::dst_reg()`: returns single-bit flagset for destination register. It coincides with `f_dst_reg`.

· `CairoWord::op0_reg()`: returns single-bit flagset for first operand register. It coincides with `f_op0_reg`.

· `CairoWord::op1_src()`: returns 3 bit flagset for second operand register. It corresponds to `f_op1_ap | f_op1_fp | f_op0_reg`.

· `CairoWord::res_log()`: returns 2 bit flagset for result logics. It corresponds to `f_res_mul | f_res_add`.

· `CairoWord::pc_up()`: returns 3 bit flagset for program counter update. It corresponds to `f_pc_jnz | f_pc_rel | f_pc_abs`.

· `CairoWord::ap_up()`: returns 2 bit flagset for allocation pointer update. It corresponds to `f_ap_one | f_ap_add`.

· `CairoWord::opcode()`: returns 3 bit flagset for operation code. It corresponds to `f_opc_aeq | f_opc_ret | f_opc_call`.

·`word::tests::test_cairo_word()`: simple unit test to check it is working, using the word `0x480680017fff8000`. 

* `CairoMemory`: this is a data structure that stores the program memory as it is being instantiated throughout computation. The first few entries of the `CairoMemory` correspond to the bytecode words resulting from the bytecode compilation of the Cairo program. As observed from various Cairo playground examples, these are normally followed by some values of the allocation and frame pointers (two entries), and it is followed by the values that will make up the witness (this includes all needed auxiliary variables created in a correct computation). We stoere in the field `publen` the original size of the memory (only compiled program). There's a couple of methods implemented for this struct.
````rust
pub struct CairoMemory {
    pub publen: u64,
    pub stack: Vec<CairoWord>>,
}
````
·`CairoMemory::new()`: creates a new memory structure from a vector of `u64`. It internally calls the constructor of `CairoWord`. 

·`CairoMemory::public()`: gets the size of the public memory. This is not needed if `publen` is a public field.  

·`CairoMemory::len()`: gets the length of the memory stack, not its capacity.

·`CairoMemory::enlarge()`: enlarges memory with enough additional slots if necessary before writing or reading.
  
·`CairoMemory::write()`: writes an element as a `CairoWord` in a given memory address. It reallocates if it needs to be enlarged.

·`CairoMemory::read()`: returns the element in a given memory address. If the address is not yet instantiated, it reallocates new memory first.

·`CairoMemory::view()`: just a visualization function to print all the elements in the memory in hexadecimal.

·`memory::tests::test_cairo_memory()`: checks writing and reading from memory with a simple set of words.

* `CairoRegisters`: A structure to store program counter, allocation pointer and frame pointer. 
````rust
pub struct CairoRegisters {
    pc: u64,
    ap: u64,
    fp: u64,
}
````
· `CairoRegsiters::new()`: creates a struct with given program counter, allocation and frame pointers.

* `CairoVariables`: A structure to store auxiliary variables throughout computation.
````rust
struct CairoVariables {
    dst: u64,
    op0: u64,
    op1: u64,
    res: u64,
    dst_dir: u64,
    op0_dir: u64,
    op1_dir: u64,
    size: u64,
}
````
· `CairoVariables::new()`: initializes variables to zero.

* `CairoStep`: A data structure to store a current step of Cairo computation. It consists of a step counter, Cairo memory, current registers, next registers, and auxiliary variables.

````rust
struct CairoStep {
    step: u64,
    memo: CairoMemory,
    curr: CairoRegisters,
    next: Option<CairoRegisters>,
    vars: CairoVariables,
}
````
· `program::add_off()`: performs the addition of a `u64` register with a `i16` offset (sums if it is positive, subtracts when negative).

· `CairoStep::execute()`: executes a Cairo step from the current registers. It internally calls the functions that compute auxiliary variables from instructions flags and update the registers.

· `CairoStep::instr()`: this function returns the current word instruction being executed. It reads memory at the address pointed to by the current program counter.

· `CairoStep::set_dst()`: this function computes the destination address reads its content.

· `CairoStep::set_op0()`: this function computes the first operand address and reads its content.

· `CairoStep::set_op1()`: this function computes the second operand address and reads its content. It also determines whether the instruction has 1 or 2 words.

· `CairoStep::set_res()`: this function computes the operation result. 

· `CairoStep::next_pc()`: this function computes the next program counter. 

· `CairoStep::next_pc()`: this function computes the next values of the allocation and frame pointers. It also writes values on memory in 'call' functions, and 'assert-equal'.

* `CairoProgram`: A Cairo full program. It starts with a memory and initial registers.
````rust
struct CairoProgram {
    memo: CairoMemory,
    regs: CairoRegisters,
}
````
· `CairoProgram::new()`: initializes the program with the initial registers and memory. 

· `CairoProgram::execute()`: for each step, it creates a new `CairoStep` and executes it. 

· `program::tests::test_cairo_step()`: tests that CairoStep works for a simple 3 words program : tempvar x = 10 return()

# UNFINISHED WORK

* `CairoInstruction`: this is a field element representing a Cairo bytecode word. It may include four additional, and redundant, fields that store the corresponding field elements for each of the components of the 64bit word: 16 flags as a vector of `F` and 3 offsets for destination address and first and second operands.
````rust
pub struct CairoInstruction<F: FftField> {
    pub word : u64,
    pub flags : Vec<F>,
    pub off_dst : F,
    pub off_op0 : F,
    pub off_op1 : F,
}
````
* `ClaimedRegisters`: this is a set of three tuples that store the claimed initial and finalization values of the three registers `pc`,`ap`,`fp` upon execution of the `CairoProgram`.
* `CairoMachine`: this is the input of the proof system. It contains a number of steps, a public memory and claimed initial and final values of the registers. 
* `ExecutionTrace`: this is a table that contains values obtained upon execution of the `CairoProgram` and describes it. Its elements are field elements.
* `CairoTable`: this is a data structure that stores the full memory after executing the `CairoProgram`, stored as field elements.
````rust
pub struct CairoTable<F: FftField> {
    pub stack: Vec<F>,
}
````
* `StateTransition`: this is the set of Cairo constraints that must be satisfied between consecutive states of the `ExecutionTrace`. 


### instruction.rs
This file includes the definition of the struct `CairoInstruction` together with some implementations for it.


* private function to convert a 64-bit Cairo word to field elements (vector of flags and 3 offsets):
````rust
fn word_to_field<F: FftField>(word: u64) -> (Vec<F>, F, F, F)
````
* private function to transform a signed 16bit integer to a field element, used to compute offsets:
````rust
fn to_field<F: FftField>(item: i16) -> F 
````






## Proof system
Both prover and verifier get as input a compiled `CairoProgram` and a set of claimed register values `ClaimedRegisters` after the execution of the program. These two will make up the so called public input of the proof system. The debug mode of the [Cairo Playground](https://www.cairo-lang.org/playground/) can be used to easily get test cases. If interesting enough, we may consider to integrate the [Cairo compiler](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/cairo/lang/compiler) directly for our tests.

### Prover: 
The first task to be done by the prover is execute-or simulate the execution of-the `CairoProgram` to obtain a correct instantiation of the `CairoMemory`. Together with these private values, the prover generates the `ExecutionTrace` and determines the witness of the relation. In order to prove the correctness of the memory (i.e. single-valued and continuity), it creates four pairs of lists (sorted and unsorted) to perform a permutation argument on them. It commits to the witness of the relation and receives two random field elements $z$ and $\alpha$ from the verifier. The former is used as a random point to evaluate the permutation argument, whereas the latter is used to linearly combine the four arguments securely. 

### Verifier

### Proof
The proof consists of a set of polynomial commitments, a permutation proof, 
