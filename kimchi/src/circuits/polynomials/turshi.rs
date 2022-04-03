//!This implements the constraints of the Cairo gates
//!
//! Cairo programs can have the following assembly-like instructions:
//! - Memory access: \[x\]
//! - Assert equal: <left_hand_op> = <right_hand_op>
//! · val
//! · \[reg1 + off_op1\]
//! · \[reg0 + off_op0\] +|* \[reg1 + off_op1\]
//! · \[reg0 + off_op0\] +|* val
//! · \[\[reg0 + off_op0\] + off_op1\]
//! - Jumps
//! · jmp abs <address>     // unconditional absolute jump
//! · jmp rel <offset>      // unconditional relative jump
//! · jmp rel <offset> if <op> != 0    // conditional jump
//! - Functions
//! · call abs <address>    // calls a function (absolute location)
//! · call rel <offset>     // calls a function (relative location)
//! · ret                   // returns to execution after the call
//! - Increments
//! · ap += <op>
//! · ap++
//!
//! A Cairo program runs accross a number of state transitions.
//! Each state transition has the following structure:
//!
//! * Has access to a read-only memory
//! * Input: 3 types of registers
//!  - pc (= program counter):  address of current instruction
//!  - ap (= allocation pointer): first free memory address
//!  - fp (= frame pointer): beginning of stack (for function arguments)
//! * Output:
//!  - next_pc: address of next instruction
//!  - next_ap: address of next free memory slot
//!  - next_fp: pointer to stack (can remain the same as fp)
//!
//!Cairo words are field elements of characteristic > 2^64
//!Cairo instructions are stored as words (63 or 64 bits - actual instruction or immediate value)
//!Instructions with immediate values are stored in 2 words
//!- The first word stores instruction
//!- The second word stores the value
//!Words of instructions consist of
//!* 3 signed offsets of 16 bits each, in the range [-2^15,2^15) biased representation
//! - off_dst (= offset from destination address): used to compute address of assignment
//! - off_op0 (= offset from first operand): used to compute address of first operand in instruction
//! - off_op1 (= offset from second operand): used to compute address of second operand in instruction
//!* 15 bits of flags divided into 7 groups
//!  When multiple bits, at most one can be 1 and the rest must be 0
//! - dst_reg \[0\] = fDST_REG : indicates what pointer off_dst refers to ( 0 => ap , 1 => fp )
//! - op0_reg \[1\] = fOP0_REG : indicates what pointer off_op0 refers to ( 0 => ap , 1 => fp )
//! - op1_src \[2..4\] : encodes the type of second operand
//!  · 0: indicates off_op1 is b in the double indexing \[\[ point + a \] + b \]
//!  · 1: indicates off_op1 is an immediate value = fOP1_VAL = 1
//!  · 2: indicates offset off_op1 relative to fp = fOP1_FP = 1
//!  · 4: indicates offset off_op1 relative to ap = fOP1_AP = 1
//! - res_logic \[5..6\]: defines (if any) arithmetic operation in right part
//!  · 0: right part is single operand
//!  · 1: right part is addition = fRES_ADD = 1
//!  · 2: right part is multiplication = fRES_MUL = 1
//! - pc_update \[7..9\]: defines the type of update for the pc
//!  · 0 = regular increase by size of current instruction
//!  · 1 = absolute jump to res address = fPC_ABS_JMP = 1
//!  · 2 = relative jump of step res = fPC_REL_JMP = 1
//!  · 4 = conditional jump (jnz) with step in op1 = fPC_JNZ = 1
//! - ap_update \[10..11\]: defines the type of update for the ap
//!  · 0: means the new ap is the same, same free position
//!  · 1: means there is an ap+=<op> instruction = fAP_INC = 1
//!  · 2: means there is an ap++ instruction = fAP_ADD1 = 1
//! - opcode \[12..14\]: encodes type of assembly instruction
//!  · 0: jumps or increments instruction
//!  · 1: call instruction = fOPC_CALL = 1
//!  · 2: return instruction = fOPC_RET = 1
//!  · 4: assert equal instruction (assignment to value or check equality) = fOPC_ASSEQ = 1
//!* in little-endian form = leftmost least significant bit
//!
//!The transition function uses 4 auxiliary values:
//!- dst: left part of instruction, destination
//!- op0: content of first operand of right part
//!- op1: content of second operand of right part
//!- res: result of the operation in the right part

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr::{self, Column};
use crate::circuits::expr::{witness_curr, witness_next, Cache, ConstantExpr, Expr, E};
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::wires::{GateWires, Wire, COLUMNS};
use crate::proof::ProofEvaluations;
use ark_ff::{FftField, Field, One};
use array_init::array_init;
use cairo::runner::ACC_PER_INS;
use cairo::{
    flags::NUM_FLAGS,
    runner::{CairoInstruction, CairoProgram, Pointers},
    word::{FlagBits, Offsets},
};
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::marker::PhantomData;

pub const CIRCUIT_GATE_COUNT: usize = 6;

// GATE-RELATED

fn gate_type_to_selector<F: FftField>(typ: GateType) -> [F; CIRCUIT_GATE_COUNT] {
    match typ {
        GateType::CairoInitial => [
            F::one(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ],
        GateType::CairoMemory => [
            F::zero(),
            F::one(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ],
        GateType::CairoInstruction => [
            F::zero(),
            F::zero(),
            F::one(),
            F::zero(),
            F::zero(),
            F::zero(),
        ],
        GateType::CairoFlags => [
            F::zero(),
            F::zero(),
            F::zero(),
            F::one(),
            F::zero(),
            F::zero(),
        ],
        GateType::CairoTransition => [
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::one(),
            F::zero(),
        ],
        GateType::CairoClaim => [
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::one(),
        ],
        _ => [F::zero(); CIRCUIT_GATE_COUNT],
    }
}

/*
fn view_table<F: Field>(table: &Vec<[F; COLUMNS]>) {
    let rows = table.len();
    for i in 0..rows {
        print!("row {}: [", i);
        for j in 0..COLUMNS {
            print!("{} , ", table[i][j].to_u64());
        }
        println!("]");
    }
}
*/

/// Returns the witness of an execution of a Cairo program in CircuitGate format
pub fn cairo_witness<F: Field>(prog: &CairoProgram<F>) -> [Vec<F>; COLUMNS] {
    // 0:    1 row for CairoInitial gate
    // 5i+1: 1 row per instruction for CairoInstruction gate
    // 5i+2: 1 row per instruction for Flags argument
    // 5i+3: 1 row per instruction for CairoTransition gate
    // 5i+4: 1 row per instruction for Cairo Zero gate
    // 5i:   1 row per instruction for CairoMemory gate
    // ...
    // 5n-4: 1 row for last instruction
    // 5n-3: 1 row for Auxiliary argument (no constraints)
    // 5n-2: 1 row for final check CairoClaim gate
    let n = prog.trace().len();
    let rows = 5 * n - 1;
    let mut table: Vec<[F; COLUMNS]> = Vec::new();
    table.resize(rows, [F::zero(); COLUMNS]);
    let mut perm = F::one();
    for (i, inst) in prog.trace().iter().enumerate() {
        let ini_wit = {
            if i == 0 {
                initial_witness(prog)
            } else {
                memory_witness(i, prog, perm)
            }
        };
        let ins_wit = instruction_witness(inst);
        let flg_wit = flag_witness(inst);
        table[5 * i] = ini_wit;
        table[5 * i + 1] = ins_wit;
        table[5 * i + 2] = flg_wit;
        perm = ini_wit[1];
        if i == n - 1 {
            // last instruction
            let fin_wit = claim_witness(prog, perm);
            table[rows - 1] = fin_wit;
        } else {
            let tra_wit = transition_witness(inst, &prog.trace()[i + 1]);
            let aux_wit = auxiliary_witness(&prog.trace()[i + 1]);
            table[5 * i + 3] = tra_wit;
            table[5 * i + 4] = aux_wit;
        }
    }

    let mut witness: [Vec<F>; COLUMNS] = Default::default();
    for col in 0..COLUMNS {
        // initialize column with zeroes
        witness[col].resize(table.len(), F::zero());
        for (row, wit) in table.iter().enumerate() {
            witness[col][row] = wit[col];
        }
    }
    witness
}

fn partial_perm<F: Field>(
    prev: F,
    this: &CairoInstruction<F>,
    adr: &[F; ACC_PER_INS],
    val: &[F; ACC_PER_INS],
) -> F {
    let pc = this.pc();
    let instr = this.instr();
    let dst = this.dst();
    let adr_dst = this.adr_dst();
    let op0 = this.op0();
    let adr_op0 = this.adr_op0();
    let op1 = this.op1();
    let adr_op1 = this.adr_op1();
    prev * ((instr + pc) * (dst + adr_dst) * (op0 + adr_op0) * (op1 + adr_op1))
        / ((adr[0] + val[0]) * (adr[1] + val[1]) * (adr[2] + val[2]) * (adr[3] + val[3]))
}

fn initial_witness<F: Field>(prog: &CairoProgram<F>) -> [F; COLUMNS] {
    let ini = 0;
    let prev = F::one();
    let adr = prog.addresses(ini);
    let val = prog.values(ini);
    let perm = partial_perm(F::one(), &prog.trace()[ini], &adr, &val);
    [
        prev,                      // previous partial permutation ratio
        perm,                      // current partial permutation ratio
        prog.trace()[ini].instr(), // for copy check of instruction with public input
        prog.ini().pc(),           // initial pc from public input
        prog.ini().ap(),           // initial ap from public input
        adr[3],
        val[3],
        adr[2],
        val[2],
        adr[1],
        val[1],
        adr[0],
        val[0],
        F::zero(),
        F::zero(),
    ]
}

fn memory_witness<F: Field>(i: usize, prog: &CairoProgram<F>, prev: F) -> [F; COLUMNS] {
    let adr = prog.addresses(i);
    let val = prog.values(i);
    let perm = partial_perm(prev, &prog.trace()[i], &adr, &val);
    [
        prev,                     // previous partial permutation ratio
        perm,                     // current partial permutation ratio
        prog.trace()[i].instr(),  // for copy check of instruction with public input
        prog.addresses(i - 1)[3], // previous sorted last address
        prog.values(i - 1)[3],    // previous sorted last value
        adr[3],
        val[3],
        adr[2],
        val[2],
        adr[1],
        val[1],
        adr[0],
        val[0],
        F::zero(),
        F::zero(),
    ]
}

fn instruction_witness<F: Field>(inst: &CairoInstruction<F>) -> [F; COLUMNS] {
    [
        inst.pc(),
        inst.ap(),
        inst.fp(),
        inst.size(),
        inst.res(),
        inst.dst(),
        inst.op1(),
        inst.op0(),
        inst.off_dst(),
        inst.off_op1(),
        inst.off_op0(),
        inst.adr_dst(),
        inst.adr_op1(),
        inst.adr_op0(),
        inst.instr(),
    ]
}

fn flag_witness<F: Field>(inst: &CairoInstruction<F>) -> [F; COLUMNS] {
    [
        inst.f_dst_fp(),
        inst.f_op0_fp(),
        inst.f_op1_val(),
        inst.f_op1_fp(),
        inst.f_op1_ap(),
        inst.f_res_add(),
        inst.f_res_mul(),
        inst.f_pc_abs(),
        inst.f_pc_rel(),
        inst.f_pc_jnz(),
        inst.f_ap_add(),
        inst.f_ap_one(),
        inst.f_opc_call(),
        inst.f_opc_ret(),
        inst.f_opc_aeq(),
    ]
}

fn transition_witness<F: Field>(
    curr: &CairoInstruction<F>,
    next: &CairoInstruction<F>,
) -> [F; COLUMNS] {
    [
        curr.pc(),
        curr.ap(),
        curr.fp(),
        curr.size(),
        curr.res(),
        curr.dst(),
        curr.op1(),
        next.pc(),
        next.ap(),
        next.fp(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
    ]
}

fn auxiliary_witness<F: Field>(next: &CairoInstruction<F>) -> [F; COLUMNS] {
    [
        next.pc(),
        next.ap(),
        next.fp(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
    ]
}

fn claim_witness<F: Field>(prog: &CairoProgram<F>, perm: F) -> [F; COLUMNS] {
    let last = prog.trace().len() - 1;
    [
        prog.trace()[last].pc(),
        prog.trace()[last].ap(),
        prog.fin().pc(),
        prog.fin().ap(),
        perm,
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
    ]
}

impl<F: FftField> CircuitGate<F> {
    /// This function creates a CairoInitial gate
    pub fn create_cairo_initial(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoInitial,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a CairoMemory gate
    pub fn create_cairo_memory(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoMemory,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a CairoInstruction gate
    pub fn create_cairo_instruction(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoInstruction,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a CairoFlags gate
    pub fn create_cairo_flags(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoFlags,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a CairoTransition gate
    pub fn create_cairo_transition(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoTransition,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a CairoClaim gate
    pub fn create_cairo_claim(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoClaim,
            wires,
            coeffs: vec![],
        }
    }

    /// Gadget generator of the whole cairo circuits from an absolute row and number of instructions
    pub fn create_cairo_gadget(
        // the absolute row in the circuit
        row: usize,
        // number of instructions
        num: usize,
    ) -> Vec<Self> {
        // 2 row per instruction for CairoInstruction gate
        // 1 row per instruction for CairoTransition gate
        // final row for CairoClaim gate
        let mut gates: Vec<CircuitGate<F>> = Vec::new();
        for i in 0..num - 1 {
            let inimem_gate = Wire::new(row + 5 * i);
            let ins_gate = Wire::new(row + 5 * i + 1);
            let flg_gate = Wire::new(row + 5 * i + 2);
            let tra_gate = Wire::new(row + 5 * i + 3);
            let aux_gate = Wire::new(row + 5 * i + 4);
            if i == 0 {
                gates.push(CircuitGate::create_cairo_initial(inimem_gate));
            } else {
                gates.push(CircuitGate::create_cairo_memory(inimem_gate));
            }
            gates.push(CircuitGate::create_cairo_instruction(ins_gate));
            gates.push(CircuitGate::create_cairo_flags(flg_gate));
            gates.push(CircuitGate::create_cairo_transition(tra_gate));
            gates.push(CircuitGate::zero(aux_gate));
        }
        // the final instruction
        let mem_gate = Wire::new(row + 5 * (num - 1));
        let ins_gate = Wire::new(row + 5 * (num - 1) + 1);
        let aux_gate = Wire::new(row + 5 * (num - 1) + 2);
        let fin_gate = Wire::new(row + 5 * (num - 1) + 3);
        gates.push(CircuitGate::create_cairo_memory(mem_gate));
        gates.push(CircuitGate::create_cairo_instruction(ins_gate));
        gates.push(CircuitGate::zero(aux_gate));
        gates.push(CircuitGate::create_cairo_claim(fin_gate));

        gates
    }

    /// verifies that the Cairo gate constraints are solved by the witness depending on its type
    pub fn verify_cairo_gate(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let curr: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let mut next: [F; COLUMNS] = array_init(|_| F::zero());
        if self.typ != GateType::Zero && self.typ != GateType::CairoClaim {
            next = array_init(|i| witness[i][row + 1]);
        }

        // column polynomials
        let polys = {
            let mut h = std::collections::HashSet::new();
            for i in 0..COLUMNS {
                h.insert(Column::Witness(i)); // column witness polynomials
            }
            // gate selector polynomials
            h.insert(Column::Index(GateType::CairoInitial));
            h.insert(Column::Index(GateType::CairoMemory));
            h.insert(Column::Index(GateType::CairoInstruction));
            h.insert(Column::Index(GateType::CairoFlags));
            h.insert(Column::Index(GateType::CairoTransition));
            h.insert(Column::Index(GateType::CairoClaim));
            h
        };

        // assign powers of alpha to these gates
        let mut alphas = Alphas::<F>::default();
        alphas.register(ArgumentType::Gate(self.typ), Instruction::<F>::CONSTRAINTS);

        // Get constraints for this circuit gate
        let constraints = circuit_gate_combined_constraints(self.typ, &alphas);

        // Linearize
        let linearized = constraints.linearize(polys).unwrap();

        // Setup proof evaluations
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let mut eval = |witness| ProofEvaluations {
            w: witness,
            z: F::rand(rng),
            s: array_init(|_| F::rand(rng)),
            generic_selector: F::zero(),
            poseidon_selector: F::zero(),
            cairo_selector: gate_type_to_selector(self.typ),
            lookup: None,
        };
        let evals = vec![eval(curr), eval(next)];

        // Setup circuit constants
        let constants = expr::Constants {
            alpha: F::rand(rng),
            beta: F::rand(rng),
            gamma: F::rand(rng),
            joint_combiner: F::rand(rng),
            endo_coefficient: cs.endo,
            mds: vec![],
        };

        let pt = F::rand(rng);

        // Evaluate constraints
        match linearized
            .constant_term
            .evaluate_(cs.domain.d1, pt, &evals, &constants)
        {
            Ok(x) => {
                if x == F::zero() {
                    Ok(())
                } else {
                    Err(format!("Invalid {:?} constraint", self.typ))
                }
            }
            Err(x) => {
                println!("{:?}", x);
                Err(format!("Failed to evaluate {:?} constraint", self.typ))
            }
        }
    }

    /// verifies that the Cairo gate constraints are solved by the witness depending on its type
    pub fn ensure_cairo_gate(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        //_cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let this: [F; COLUMNS] = array_init(|i| witness[i][row]);

        match self.typ {
            GateType::CairoInitial => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_initial(&this, &next)
            }
            GateType::CairoMemory => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_memory(&this, &next)
            }
            GateType::CairoInstruction => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_instruction(&this, &next)
            }
            GateType::CairoFlags => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_flags(&this, &next)
            }
            GateType::CairoTransition => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_transition(&this, &next)
            }
            GateType::Zero => Ok(()),
            GateType::CairoClaim => CircuitGate::ensure_claim(&this), // CircuitGate::ensure_transition(&this),
            _ => Err(
                "Incorrect GateType: expected CairoInstruction, CairoTransition, or CairoClaim"
                    .to_string(),
            ),
        }
    }

    fn ensure_initial(this: &[F], next: &[F]) -> Result<(), String> {
        let prev = this[0]; // previous partial ratio
        let perm = this[1]; // current partial ratio
        let copy = this[2]; // constraint for instruction from public input
        let pc_ini = this[3]; // copy from public input
        let ap_ini = this[4]; // copy from public input
        let adr: Vec<F> = (0..ACC_PER_INS).map(|i| this[11 - 2 * i]).collect(); // adr[0] = curr(11), adr[1] = curr(9), adr[2] = curr(7), adr[3] = curr(5)
        let val: Vec<F> = (0..ACC_PER_INS).map(|i| this[12 - 2 * i]).collect(); // val[0] = curr(12), val[1] = curr(10), val[2] = curr(8), val[3] = curr(6)

        // load address / value pairs from next row
        let pc = next[0];
        let ap0 = next[1];
        let fp0 = next[2];
        let dst = next[5];
        let op1 = next[6];
        let op0 = next[7];
        let adr_dst = next[11];
        let adr_op1 = next[12];
        let adr_op0 = next[13];
        let instr = next[14];

        ensure_eq!(F::zero(), ap0 - ap_ini, "Bad initial ap");
        ensure_eq!(F::zero(), fp0 - ap_ini, "Bad initial fp");
        ensure_eq!(F::zero(), pc - pc_ini, "Bad initial pc");
        ensure_eq!(F::zero(), copy - instr, "Bad instruction copy");
        for i in 0..ACC_PER_INS - 1 {
            ensure_eq!(
                F::zero(),
                (adr[i + 1] - adr[i]) * (adr[i + 1] - adr[i] - F::one()),
                "Memory is not continue"
            );
            ensure_eq!(
                F::zero(),
                (val[i + 1] - val[i]) * (adr[i + 1] - adr[i] - F::one()),
                "Values are not singular"
            );
        }

        // TODO (querolita): Fix when alpha and zeta are added
        ensure_eq!(
            F::zero(),
            prev * (pc + instr) * (adr_dst + dst) * (adr_op0 + op0) * (adr_op1 + op1)
                - perm
                    * (adr[0] + val[0])
                    * (adr[1] + val[1])
                    * (adr[2] + val[2])
                    * (adr[3] + val[3]),
            "Failed partial permutation ratio"
        );

        Ok(())
    }

    fn ensure_memory(this: &[F], next: &[F]) -> Result<(), String> {
        let prev = this[0]; // previous partial ratio
        let perm = this[1]; // current partial ratio
        let copy = this[2]; // constraint for instruction from public input
        let mut adr: Vec<F> = (0..ACC_PER_INS + 1).map(|i| this[11 - 2 * i]).collect(); // adr[0] = curr(11), adr[1] = curr(9), adr[2] = curr(7), adr[3] = curr(5), adr[4] = curr[3]
        let mut val: Vec<F> = (0..ACC_PER_INS + 1).map(|i| this[12 - 2 * i]).collect(); // val[0] = curr(12), val[1] = curr(10), val[2] = curr(8), val[3] = curr(6), val[4] = curr[4]
        adr.rotate_right(1);
        val.rotate_right(1);
        // load address / value pairs from next row
        let pc = next[0];
        let dst = next[5];
        let op1 = next[6];
        let op0 = next[7];
        let adr_dst = next[11];
        let adr_op1 = next[12];
        let adr_op0 = next[13];
        let instr = next[14];

        ensure_eq!(F::zero(), copy - instr, "Bad instruction copy");
        for i in 0..ACC_PER_INS {
            ensure_eq!(
                F::zero(),
                (adr[i + 1] - adr[i]) * (adr[i + 1] - adr[i] - F::one()),
                "Memory is not continue"
            );
            ensure_eq!(
                F::zero(),
                (val[i + 1] - val[i]) * (adr[i + 1] - adr[i] - F::one()),
                "Values are not singular"
            );
        }

        // TODO (querolita): Fix when alpha and zeta are added
        ensure_eq!(
            F::zero(),
            prev * (pc + instr) * (adr_dst + dst) * (adr_op0 + op0) * (adr_op1 + op1)
                - perm
                    * (adr[1] + val[1])
                    * (adr[2] + val[2])
                    * (adr[3] + val[3])
                    * (adr[4] + val[4]),
            "Failed partial permutation ratio"
        );

        Ok(())
    }

    fn ensure_instruction(vars: &[F], flags: &[F]) -> Result<(), String> {
        let pc = vars[0];
        let ap = vars[1];
        let fp = vars[2];
        let size = vars[3];
        let res = vars[4];
        let dst = vars[5];
        let op1 = vars[6];
        let op0 = vars[7];
        let off_dst = vars[8];
        let off_op1 = vars[9];
        let off_op0 = vars[10];
        let adr_dst = vars[11];
        let adr_op1 = vars[12];
        let adr_op0 = vars[13];
        let instr = vars[14];

        let f_dst_fp = flags[0];
        let f_op0_fp = flags[1];
        let f_op1_val = flags[2];
        let f_op1_fp = flags[3];
        let f_op1_ap = flags[4];
        let f_res_add = flags[5];
        let f_res_mul = flags[6];
        let f_pc_abs = flags[7];
        let f_pc_rel = flags[8];
        let f_pc_jnz = flags[9];
        let f_ap_inc = flags[10];
        let f_ap_one = flags[11];
        let f_opc_call = flags[12];
        let f_opc_ret = flags[13];
        let f_opc_aeq = flags[14];

        let zero = F::zero();
        let one = F::one();

        // FLAGS RELATED

        // check last flag is a zero
        // f15 == 0
        //ensure_eq!(zero, f15, "last flag is nonzero");

        // check booleanity of flags
        // fi * (1-fi) == 0 for i=[0..15)
        for &flag in flags.iter().take(NUM_FLAGS - 1) {
            ensure_eq!(zero, flag * (one - flag), "non-boolean flags");
        }

        // well formness of instruction
        let shape = {
            let shift = F::from(2u32.pow(15)); // 2^15;
            let pow16 = shift.double(); // 2^16
            let dst_sft = off_dst + shift;
            let op0_sft = off_op0 + shift;
            let op1_sft = off_op1 + shift;
            // recompose instruction as: flags[14..0] | op1_sft | op0_sft | dst_sft
            let mut aux = flags[14];
            for i in (0..14).rev() {
                aux = aux * F::from(2u32) + flags[i];
            }
            // complete with "flags" * 2^48 + op1_sft * 2^32 + op0_sft * 2^16 + dst_sft
            ((aux * pow16 + op1_sft) * pow16 + op0_sft) * pow16 + dst_sft
        };
        ensure_eq!(
            zero,
            instr - shape,
            "wrong decomposition of the instruction"
        );

        // check no two flags of same set are nonzero
        let op1_set = f_op1_ap + f_op1_fp + f_op1_val;
        let res_set = f_res_mul + f_res_add;
        let pc_set = f_pc_jnz + f_pc_rel + f_pc_abs;
        let ap_set = f_ap_one + f_ap_inc;
        let opcode_set = f_opc_aeq + f_opc_ret + f_opc_call;
        ensure_eq!(
            zero,
            op1_set * (one - op1_set),
            "invalid format of `op1_src`"
        );

        ensure_eq!(
            zero,
            res_set * (one - res_set),
            "invalid format of `res_log`"
        );
        ensure_eq!(zero, pc_set * (one - pc_set), "invalid format of `pc_up`");
        ensure_eq!(zero, ap_set * (one - ap_set), "invalid format of `ap_up`");
        ensure_eq!(
            zero,
            opcode_set * (one - opcode_set),
            "invalid format of `opcode`"
        );

        // OPERANDS RELATED

        // * Destination address
        // if dst_reg = 0 : dst_dir = ap + off_dst
        // if dst_reg = 1 : dst_dir = fp + off_dst
        ensure_eq!(
            adr_dst,
            f_dst_fp * fp + (one - f_dst_fp) * ap + off_dst,
            "invalid destination address"
        );

        // * First operand address
        // if op0_reg = 0 : op0_dir = ap + off_dst
        // if op0_reg = 1 : op0_dir = fp + off_dst
        ensure_eq!(
            adr_op0,
            f_op0_fp * fp + (one - f_op0_fp) * ap + off_op0,
            "invalid first operand address"
        );

        // * Second operand address
        ensure_eq!(
            adr_op1, //                                        op1_dir = ..
            (f_op1_ap * ap                                  // if op1_src == 4 : ap
            + f_op1_fp * fp                                 // if op1_src == 2 : fp
            + f_op1_val * pc                                // if op1_src == 1 : pc
            + (one - f_op1_fp - f_op1_ap - f_op1_val) * op0 // if op1_src == 0 : op0
            + off_op1), //                                                           + off_op1
            "invalid second operand address"
        );

        // OPERATIONS RELATED

        // * Check value of result
        ensure_eq!(
            (one - f_pc_jnz) * res, //               if  pc_up != 4 : res = ..  // no res in conditional jumps
            f_res_mul * op0 * op1                 // if res_log = 2 : op0 * op1
            + f_res_add * (op0 + op1)             // if res_log = 1 : op0 + op1
            + (one - f_res_add - f_res_mul) * op1, // if res_log = 0 : op1
            "invalid result"
        );

        // * Check storage of current fp for a call instruction
        ensure_eq!(
            zero,
            f_opc_call * (dst - fp),
            "current fp after call not stored"
        ); // if opcode = 1 : dst = fp

        // * Check storage of next instruction after a call instruction
        ensure_eq!(
            zero,
            f_opc_call * (op0 - (pc + size)),
            "next instruction after call not stored"
        ); // if opcode = 1 : op0 = pc + size

        // * Check destination = result after assert-equal
        ensure_eq!(zero, f_opc_aeq * (dst - res), "false assert equal"); // if opcode = 4 : dst = res

        Ok(())
    }

    fn ensure_flags(curr: &[F], next: &[F]) -> Result<(), String> {
        let f_pc_abs = curr[7];
        let f_pc_rel = curr[8];
        let f_pc_jnz = curr[9];
        let f_ap_inc = curr[10];
        let f_ap_one = curr[11];
        let f_opc_call = curr[12];
        let f_opc_ret = curr[13];
        let pc = next[0];
        let ap = next[1];
        let fp = next[2];
        let size = next[3];
        let res = next[4];
        let dst = next[5];
        let op1 = next[6];
        let pcup = next[7];
        let apup = next[8];
        let fpup = next[9];

        let zero = F::zero();
        let one = F::one();
        let two = F::from(2u16);

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(
            apup, //               next_ap =
            ap                   //             ap +
            + f_ap_inc * res      //  if ap_up == 1 : res
            + f_ap_one           //  if ap_up == 2 : 1
            + f_opc_call.double(), // if opcode == 1 : 2
            "wrong ap update"
        );

        // * Check next frame pointer
        ensure_eq!(
            fpup, //                                       next_fp =
            f_opc_call * (ap + two)      // if opcode == 1      : ap + 2
            + f_opc_ret * dst                    // if opcode == 2      : dst
            + (one - f_opc_call - f_opc_ret) * fp, // if opcode == 4 or 0 : fp
            "wrong fp update"
        );

        // * Check next program counter
        ensure_eq!(
            zero,
            f_pc_jnz * (dst * res - one) * (pcup - (pc + size)), // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
            "wrong pc update"
        );
        ensure_eq!(
            zero,
            f_pc_jnz * dst * (pcup - (pc + op1))                  // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
            + (one - f_pc_jnz) * pcup                             // <=> pc_up = {0,1,2} : next_pc = ... // not a conditional jump
                - (one - f_pc_abs - f_pc_rel - f_pc_jnz) * (pc + size) // <=> pc_up = 0 : next_pc = pc + size // common case
                - f_pc_abs * res                                     // <=> pc_up = 1 : next_pc = res       // absolute jump
                - f_pc_rel * (pc + res), //                             <=> pc_up = 2 : next_pc = pc + res  // relative jump
            "wrong pc update"
        );

        Ok(())
    }

    fn ensure_transition(curr: &[F], next: &[F]) -> Result<(), String> {
        let pcup = curr[7];
        let apup = curr[8];
        let fpup = curr[9];
        let next_pc = next[0];
        let next_ap = next[1];
        let next_fp = next[2];

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(next_ap, apup, "wrong next allocation pointer");

        // * Check next frame pointer
        ensure_eq!(next_fp, fpup, "wrong next frame pointer");

        // * Check next program counter
        ensure_eq!(next_pc, pcup, "wrong next program counter");

        Ok(())
    }

    fn ensure_claim(claim: &[F]) -> Result<(), String> {
        let pc_n = claim[0];
        let ap_n = claim[1];
        let pc_fin = claim[2];
        let ap_fin = claim[3];
        let perm = claim[4];

        // * Check final pc, ap, and permutation ratio is 1
        ensure_eq!(F::zero(), pc_n - pc_fin, "wrong final pc");
        ensure_eq!(F::zero(), ap_n - ap_fin, "wrong final ap");
        ensure_eq!(F::one(), perm, "sorted memory is not permutation");

        Ok(())
    }
}

//~ The Kimchi 15 columns could be:
//~ GateType     Initial  |  Memory   Instruction   Aux | (Flags+Transition+Aux)       Claim
//~    row   ->  0           5i       5i+1          5i+2       5i+3        5i+4        5n-1
//~             ---------------------------------------------------------------------------------
//~     0    ·   © prev   =  © prev   pc            fDST_FP    © pc        © next_pc   © pc\[n-1\]
//~     1    ·   perm     =  perm     ap            fOP0_FP    © ap        © next_ap   © ap\[n-1\]
//~  c  2    ·   ® copy   =  ® copy   fp            fOP1_VAL   © fp        © next_fp   ® pc_fin
//~  o  3    ·   ® pc_ini    © m_1    size          fOP1_FP    © size                  ® ap_fin
//~  l  4    ·   ® ap_ini    © v_1    res           fOP1_AP    © res                   © perm\[n-1\]
//~  |  5    ·   mem3     =  mem3     dst           fRES_ADD   © dst
//~  v  6    ·   val3     =  val3     op1           fRES_MUL   © op1
//~     7        mem2     =  mem2     op0           fPC_ABS    pcup
//~     8        val2     =  val2     off_dst       fPC_REL    apup
//~     9        mem1     =  mem1     off_op1       fPC_JNZ    fpup
//~     10       val1     =  val1     off_op0       fAP_ADD
//~     11       mem0     =  mem0     adr_dst       fAP_ONE
//~     12       val0     =  val0     adr_op1       fOPC_CALL
//~     13                            adr_op0       fOPC_RET
//~     14                            instr         fOPC_AEQ

// CONSTRAINTS-RELATED

/// Returns the expression corresponding to the literal "2"
fn two<F: Field>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u16.into())) // 2
}

/// Combines the constraints for the Cairo gates
pub fn gate_combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    Initial::combined_constraints(alphas)
        + Memory::combined_constraints(alphas)
        + Instruction::combined_constraints(alphas)
        + Flags::combined_constraints(alphas)
        + Transition::combined_constraints(alphas)
        + Claim::combined_constraints(alphas)
}

/// Combines the constraints for the Cairo gates depending on its type
pub fn circuit_gate_combined_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::CairoInitial => Initial::combined_constraints(alphas),
        GateType::CairoMemory => Memory::combined_constraints(alphas),
        GateType::CairoInstruction => Instruction::combined_constraints(alphas),
        GateType::CairoFlags => Flags::combined_constraints(alphas),
        GateType::CairoTransition => Transition::combined_constraints(alphas),
        GateType::Zero => E::literal(F::zero()),
        GateType::CairoClaim => Claim::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

pub struct Initial<F>(PhantomData<F>);

impl<F> Argument<F> for Initial<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoInitial);
    const CONSTRAINTS: u32 = 11;

    /// Generates the constraints for the Cairo initial claim and first memory checks
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        let prev = witness_curr(0); // previous partial ratio
        let perm = witness_curr(1); // current partial ratio
        let copy = witness_curr(2); // constraint for instruction from public input
        let pc_ini = witness_curr(3); // copy from public input
        let ap_ini = witness_curr(4); // copy from public input
        let adr: Vec<E<F>> = (0..ACC_PER_INS).map(|i| witness_curr(11 - 2 * i)).collect(); // adr[0] = curr(11), adr[1] = curr(9), adr[2] = curr(7), adr[3] = curr(5), adr[4] = curr[3]
        let val: Vec<E<F>> = (0..ACC_PER_INS).map(|i| witness_curr(12 - 2 * i)).collect(); // val[0] = curr(12), val[1] = curr(10), val[2] = curr(8), val[3] = curr(6), val[4] = curr[4]

        // load address / value pairs from next row
        let pc = witness_next(0);
        let ap0 = witness_next(1);
        let fp0 = witness_next(2);
        let dst = witness_next(5);
        let op1 = witness_next(6);
        let op0 = witness_next(7);
        let adr_dst = witness_next(11);
        let adr_op1 = witness_next(12);
        let adr_op0 = witness_next(13);
        let instr = witness_next(14);

        let one = E::literal(F::one());

        // Initial claim
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![ap0 - ap_ini.clone()]; // ap0 = ini_ap
        constraints.push(fp0 - ap_ini); // fp0 = ini_ap
        constraints.push(pc.clone() - pc_ini); // pc0 = ini_pc

        // check correct duplicate of instruction
        constraints.push(copy - instr.clone());

        for i in 0..ACC_PER_INS - 1 {
            // Continuity of memory addresses
            constraints.push(
                (adr[i + 1].clone() - adr[i].clone())
                    * (adr[i + 1].clone() - adr[i].clone() - one.clone()),
            );
            // Singularity of memory values
            constraints.push(
                (val[i + 1].clone() - val[i].clone())
                    * (adr[i + 1].clone() - adr[i].clone() - one.clone()),
            );
        }

        // TODO (querolita): Fix when alpha and zeta are added
        constraints.push(
            prev * (pc + instr) * (adr_dst + dst) * (adr_op0 + op0) * (adr_op1 + op1)
                - perm
                    * (adr[0].clone() + val[0].clone())
                    * (adr[1].clone() + val[1].clone())
                    * (adr[2].clone() + val[2].clone())
                    * (adr[3].clone() + val[3].clone()),
        );

        constraints
    }
}

pub struct Memory<F>(PhantomData<F>);
impl<F> Argument<F> for Memory<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoMemory);
    const CONSTRAINTS: u32 = 10;

    /// Generates the constraints for the Cairo memory
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        // load sorted address / value pairs
        let prev = witness_curr(0); // previous partial ratio
        let perm = witness_curr(1); // current partial ratio
        let copy = witness_curr(2); // constraint for instruction from public input
        let mut adr: Vec<E<F>> = (0..ACC_PER_INS + 1)
            .map(|i| witness_curr(11 - 2 * i))
            .collect(); // adr[0] = curr(11), adr[1] = curr(9), adr[2] = curr(7), adr[3] = curr(5), adr[4] = curr[3]
        let mut val: Vec<E<F>> = (0..ACC_PER_INS + 1)
            .map(|i| witness_curr(12 - 2 * i))
            .collect(); // val[0] = curr(12), val[1] = curr(10), val[2] = curr(8), val[3] = curr(6), val[4] = curr[4]
        adr.rotate_right(1); // mem-1, mem0, mem1, mem2, mem3
        val.rotate_right(1); // val-1, val0, val1, val2, val3

        // load address / value pairs from next row
        let pc = witness_next(0);
        let dst = witness_next(5);
        let op1 = witness_next(6);
        let op0 = witness_next(7);
        let adr_dst = witness_next(11);
        let adr_op1 = witness_next(12);
        let adr_op0 = witness_next(13);
        let instr = witness_next(14);

        let one = E::literal(F::one());

        // Initialize constraints vector
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![copy - instr.clone()]; // check correct duplicate of instruction

        for i in 0..ACC_PER_INS {
            // Continuity of memory addresses
            constraints.push(
                (adr[i + 1].clone() - adr[i].clone())
                    * (adr[i + 1].clone() - adr[i].clone() - one.clone()),
            );
            // Singularity of memory values
            constraints.push(
                (val[i + 1].clone() - val[i].clone())
                    * (adr[i + 1].clone() - adr[i].clone() - one.clone()),
            );
        }

        // TODO (querolita): Fix when alpha and zeta are added
        constraints.push(
            prev * (pc + instr) * (adr_dst + dst) * (adr_op0 + op0) * (adr_op1 + op1)
                - perm
                    * (adr[1].clone() + val[1].clone())
                    * (adr[2].clone() + val[2].clone())
                    * (adr[3].clone() + val[3].clone())
                    * (adr[4].clone() + val[4].clone()),
        );

        constraints
    }
}

pub struct Instruction<F>(PhantomData<F>);

impl<F> Argument<F> for Instruction<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoInstruction);
    const CONSTRAINTS: u32 = 28;

    /// Generates the constraints for the Cairo instruction
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        // load all variables of the witness corresponding to Cairoinstruction gates
        let pc = witness_curr(0);
        let ap = witness_curr(1);
        let fp = witness_curr(2);
        let size = witness_curr(3);
        let res = witness_curr(4);
        let dst = witness_curr(5);
        let op1 = witness_curr(6);
        let op0 = witness_curr(7);
        let off_dst = witness_curr(8);
        let off_op1 = witness_curr(9);
        let off_op0 = witness_curr(10);
        let adr_dst = witness_curr(11);
        let adr_op1 = witness_curr(12);
        let adr_op0 = witness_curr(13);
        let instr = witness_curr(14);
        // Load flags from the following row
        let f_dst_fp = witness_next(0);
        let f_op0_fp = witness_next(1);
        let f_op1_val = witness_next(2);
        let f_op1_fp = witness_next(3);
        let f_op1_ap = witness_next(4);
        let f_res_add = witness_next(5);
        let f_res_mul = witness_next(6);
        let f_pc_abs = witness_next(7);
        let f_pc_rel = witness_next(8);
        let f_pc_jnz = witness_next(9);
        let f_ap_add = witness_next(10);
        let f_ap_one = witness_next(11);
        let f_opc_call = witness_next(12);
        let f_opc_ret = witness_next(13);
        let f_opc_aeq = witness_next(14);

        // collect flags in its natural ordering
        let flags: Vec<Expr<ConstantExpr<F>>> =
            (0..NUM_FLAGS - 1).map(|i| witness_next(i)).collect();

        // LIST OF CONSTRAINTS
        // -------------------
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![];
        let mut cache = Cache::default();

        // INSTRUCTIONS RELATED

        // * Check last flag is always zero is redundant with wellformness check

        // * Check booleanity of all flags
        // fi * (1-fi) == 0 for i=[0..15)
        for flag in flags.iter().take(NUM_FLAGS - 1) {
            constraints.push(flag.clone() * (E::one() - flag.clone()));
        }

        // * Check no two flagbits of the same flagset are nonzero
        // TODO(querolita): perhaps these are redundant considering all of the logics below
        let op1_src = cache.cache(f_op1_ap.clone() + f_op1_fp.clone() + f_op1_val.clone());
        let res_log = cache.cache(f_res_mul.clone() + f_res_add.clone());
        let pc_up = cache.cache(f_pc_jnz.clone() + f_pc_rel + f_pc_abs);
        let ap_up = cache.cache(f_ap_one + f_ap_add);
        let opcode = cache.cache(f_opc_aeq.clone() + f_opc_ret + f_opc_call.clone());
        constraints.push(op1_src.clone() * (E::one() - op1_src));
        constraints.push(res_log.clone() * (E::one() - res_log));
        constraints.push(pc_up.clone() * (E::one() - pc_up));
        constraints.push(ap_up.clone() * (E::one() - ap_up));
        constraints.push(opcode.clone() * (E::one() - opcode));

        // * Shape of instruction
        let shape = {
            let shift = cache.cache(E::Pow(Box::new(two()), 15)); // 2^15;
            let pow16 = cache.cache(Expr::Double(Box::new(shift.clone()))); // 2^16
            let dst_sft = off_dst.clone() + shift.clone();
            let op0_sft = off_op0.clone() + shift.clone();
            let op1_sft = off_op1.clone() + shift;
            // recompose instruction as: flags[14..0] | op1_sft | op0_sft | dst_sft
            let mut aux: Expr<ConstantExpr<F>> = flags[14].clone();
            for i in (0..14).rev() {
                aux = aux * two() + flags[i].clone();
            }
            // complete with "flags" * 2^48 + op1_sft * 2^32 + op0_sft * 2^16 + dst_sft
            aux = ((aux * pow16.clone() + op1_sft) * pow16.clone() + op0_sft) * pow16 + dst_sft;
            aux
        };
        constraints.push(instr - shape);

        // OPERANDS RELATED

        // * Destination address
        // if dst_fp = 0 : dst_dir = ap + off_dst
        // if dst_fp = 1 : dst_dir = fp + off_dst
        constraints.push(
            f_dst_fp.clone() * fp.clone() + (E::one() - f_dst_fp) * ap.clone() + off_dst - adr_dst,
        );

        // * First operand address
        // if op0_fp = 0 : op0_dir = ap + off_dst
        // if op0_fp = 1 : op0_dir = fp + off_dst
        constraints.push(
            f_op0_fp.clone() * fp.clone() + (E::one() - f_op0_fp) * ap.clone() + off_op0 - adr_op0,
        );

        // * Second operand address
        constraints.push(
            adr_op1                                                                                  //         op1_dir = ..
          - (f_op1_ap.clone() * ap                                                     // if op1_src == 4 : ap
          + f_op1_fp.clone() * fp.clone()                                                      // if op1_src == 2 : fp
          + f_op1_val.clone() * pc.clone()                                                     // if op1_src == 1 : pc
          + (E::one() - f_op1_fp - f_op1_ap - f_op1_val) * op0.clone() // if op1_src == 0 : op0
          + off_op1), //                                                                                        + off_op1
        );

        // OPERATIONS-RELATED

        // * Check value of result
        constraints.push(
            (E::one() - f_pc_jnz) * res.clone()                              // if pc_up != 4 : res = ..        // no res in conditional jumps
          - (f_res_mul.clone() * op0.clone() * op1.clone()                     //      if res_log = 2 : op0 * op1
          + f_res_add.clone() * (op0.clone() + op1.clone())                    //      if res_log = 1 : op0 + op1
          + (E::one() - f_res_add - f_res_mul) * op1), //      if res_log = 0 : op1
        );

        // * Check storage of current fp for a call instruction
        // <=> assert_eq!(dst, fp);
        constraints.push(f_opc_call.clone() * (dst.clone() - fp)); // if opcode = 1 : dst = fp

        // * Check storage of next instruction after a call instruction
        // <=> assert_eq!(op0, pc + size); // checks [ap+1] contains instruction after call
        constraints.push(f_opc_call * (op0 - (pc + size))); // if opcode = 1 : op0 = pc + size

        // * Check destination = result after assert-equal
        // <=> assert_eq!(res, dst);
        constraints.push(f_opc_aeq * (dst - res)); // if opcode = 4 : dst = res

        constraints
    }
}

pub struct Flags<F>(PhantomData<F>);

impl<F> Argument<F> for Flags<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoFlags);
    const CONSTRAINTS: u32 = 4;

    /// Generates the constraints for the Cairo flags
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        // Load current row
        let f_pc_abs = witness_curr(7);
        let f_pc_rel = witness_curr(8);
        let f_pc_jnz = witness_curr(9);
        let f_ap_add = witness_curr(10);
        let f_ap_one = witness_curr(11);
        let f_opc_call = witness_curr(12);
        let f_opc_ret = witness_curr(13);
        // Load next row
        let pc = witness_next(0);
        let ap = witness_next(1);
        let fp = witness_next(2);
        let size = witness_next(3);
        let res = witness_next(4);
        let dst = witness_next(5);
        let op1 = witness_next(6);
        let pcup = witness_next(7);
        let apup = witness_next(8);
        let fpup = witness_next(9);

        // REGISTERS-RELATED
        // * Check next allocation pointer
        //  next_ap =
        //             ap +
        //  if ap_up == 1  : res
        //  if ap_up == 2  : 1
        // if opcode == 1  : 2
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![
            apup - (ap.clone() + f_ap_add * res.clone() + f_ap_one + f_opc_call.clone().double()),
        ];

        // * Check next frame pointer
        constraints.push(
            fpup                                               //             next_fp =
                - (f_opc_call.clone() * (ap + two())           // if opcode == 1      : ap + 2
                + f_opc_ret.clone() * dst.clone()              // if opcode == 2      : dst
                + (E::one() - f_opc_call - f_opc_ret) * fp ), // if opcode == 4 or 0 : fp
        );

        // * Check next program counter (pc update)
        constraints.push(
            f_pc_jnz.clone()
                * (dst.clone() * res.clone() - E::one())
                * (pcup.clone() - (pc.clone() + size.clone())),
        ); // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
        constraints.push(
            f_pc_jnz.clone() * dst * (pcup.clone() - (pc.clone() + op1))                         // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
                    + (E::one() - f_pc_jnz.clone()) * pcup                                                       // <=> pc_up = {0,1,2}        : next_pc = ... // not a conditional jump
                        - (E::one() - f_pc_abs.clone() - f_pc_rel.clone() - f_pc_jnz) * (pc.clone() + size) // <=> pc_up = 0              : next_pc = pc + size // common case
                        - f_pc_abs * res.clone()                                                                    // <=> pc_up = 1              : next_pc = res       // absolute jump
                        - f_pc_rel * (pc + res), //                                                    <=> pc_up = 2              : next_pc = pc + res  // relative jump
        );
        constraints
    }
}

pub struct Transition<F>(PhantomData<F>);

impl<F> Argument<F> for Transition<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoTransition);
    const CONSTRAINTS: u32 = 3;

    /// Generates the constraints for the Cairo transition
    ///     Accesses Curr and Next rows (Next only first 3 entries)
    fn constraints() -> Vec<E<F>> {
        // load computed updated registers
        let pcup = witness_curr(7);
        let apup = witness_curr(8);
        let fpup = witness_curr(9);
        // load next registers
        let next_pc = witness_next(0);
        let next_ap = witness_next(1);
        let next_fp = witness_next(2);

        // * Check equality (like a copy constraint)

        let constraints: Vec<Expr<ConstantExpr<F>>> =
            vec![next_pc - pcup, next_ap - apup, next_fp - fpup];

        constraints
    }
}

pub struct Claim<F>(PhantomData<F>);

impl<F> Argument<F> for Claim<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoClaim);
    const CONSTRAINTS: u32 = 3;

    /// Generates the constraints for the Cairo final claim
    ///     Accesses Curr row only
    fn constraints() -> Vec<E<F>> {
        let pc_n = witness_curr(0);
        let ap_n = witness_curr(1);
        let pc_fin = witness_curr(2);
        let ap_fin = witness_curr(3);
        let perm = witness_curr(4);

        // check final ap
        // check final pc
        // check final permutation ratio is 1
        let constraints: Vec<Expr<ConstantExpr<F>>> =
            vec![ap_n - ap_fin, pc_n - pc_fin, perm - E::literal(F::one())];

        constraints
    }
}
