//! This module represents a run of a Cairo program as a series of consecutive
//! execution steps, each of which define the execution logic of Cairo instructions

use crate::{
    flags::*,
    memory::CairoMemory,
    word::{CairoWord, FlagBits, FlagSets, Offsets},
};
use ark_ff::Field;

/// A structure to store program counter, allocation pointer and frame pointer
#[derive(Clone, Copy)]
pub struct CairoState<F> {
    /// Program counter: points to address in memory
    pc: F,
    /// Allocation pointer: points to first free space in memory
    ap: F,
    /// Frame pointer: points to the beginning of the stack in memory (for arguments)
    fp: F,
}

/// This trait contains functions to obtain the Cairo pointers (program counter, allocation pointer and frame pointer)
pub trait Pointers<F> {
    /// Returns the program counter
    fn pc(&self) -> F;

    /// Returns the allocation pointer
    fn ap(&self) -> F;

    /// Returns the frame pointer
    fn fp(&self) -> F;
}

impl<F: Field> CairoState<F> {
    /// Creates a new triple of pointers
    pub fn new(pc: F, ap: F, fp: F) -> Self {
        CairoState { pc, ap, fp }
    }
}

impl<F: Field> Pointers<F> for CairoState<F> {
    fn pc(&self) -> F {
        self.pc
    }

    fn ap(&self) -> F {
        self.ap
    }

    fn fp(&self) -> F {
        self.fp
    }
}

#[derive(Clone, Copy)]
/// A structure to store auxiliary variables throughout computation
pub struct CairoContext<F> {
    /// Destination
    dst: Option<F>,
    /// First operand
    op0: Option<F>,
    /// Second operand
    op1: Option<F>,
    /// Result
    res: Option<F>,
    /// Destination address
    adr_dst: F,
    /// First operand address
    adr_op0: F,
    /// Second operand address
    adr_op1: F,
    /// Size of the instruction
    size: F,
}

impl<F: Field> Default for CairoContext<F> {
    /// This function creates an instance of a default [CairoContext] struct
    fn default() -> Self {
        Self {
            dst: None,
            op0: None,
            op1: None,
            res: None,
            adr_dst: F::zero(),
            adr_op0: F::zero(),
            adr_op1: F::zero(),
            size: F::zero(),
        }
    }
}

#[derive(Clone, Copy)]
/// This structure stores all the needed information relative to an instruction at a given step of computation
pub struct CairoInstruction<F> {
    /// instruction word
    word: CairoWord<F>,
    /// pointers
    ptrs: CairoState<F>,
    /// auxiliary variables
    vars: CairoContext<F>,
}

impl<F: Field> CairoInstruction<F> {
    /// Creates a [CairoInstruction]
    pub fn new(word: CairoWord<F>, ptrs: CairoState<F>, vars: CairoContext<F>) -> Self {
        Self { word, ptrs, vars }
    }

    /// Returns the field element corresponding to the [CairoInstruction]
    pub fn instr(&self) -> F {
        self.word.word()
    }

    /// Returns the size of the instruction
    pub fn size(&self) -> F {
        self.vars.size
    }

    /// Returns the result of the instruction
    pub fn res(&self) -> F {
        self.vars.res.expect("None res")
    }

    /// Returns the destination of the instruction
    pub fn dst(&self) -> F {
        self.vars.dst.expect("None dst")
    }

    /// Returns the first operand of the instruction
    pub fn op0(&self) -> F {
        self.vars.op0.expect("None op0")
    }

    /// Returns the second operand of the instruction
    pub fn op1(&self) -> F {
        self.vars.op1.expect("None op1")
    }

    /// Returns the destination address of the instruction
    pub fn adr_dst(&self) -> F {
        self.vars.adr_dst
    }

    /// Returns the first operand address of the instruction
    pub fn adr_op0(&self) -> F {
        self.vars.adr_op0
    }

    /// Returns the second operand address of the instruction
    pub fn adr_op1(&self) -> F {
        self.vars.adr_op1
    }
}

impl<F: Field> Pointers<F> for CairoInstruction<F> {
    fn pc(&self) -> F {
        self.ptrs.pc // Returns the current program counter
    }

    fn ap(&self) -> F {
        self.ptrs.ap //Returns the current allocation pointer
    }

    fn fp(&self) -> F {
        self.ptrs.fp // Returns the current program counter
    }
}

impl<F: Field> Offsets<F> for CairoInstruction<F> {
    fn off_dst(&self) -> F {
        self.word.off_dst()
    }

    fn off_op0(&self) -> F {
        self.word.off_op0()
    }

    fn off_op1(&self) -> F {
        self.word.off_op1()
    }
}

impl<F: Field> FlagBits<F> for CairoInstruction<F> {
    fn f_dst_fp(&self) -> F {
        self.word.f_dst_fp()
    }

    fn f_op0_fp(&self) -> F {
        self.word.f_op0_fp()
    }

    fn f_op1_val(&self) -> F {
        self.word.f_op1_val()
    }

    fn f_op1_fp(&self) -> F {
        self.word.f_op1_fp()
    }

    fn f_op1_ap(&self) -> F {
        self.word.f_op1_ap()
    }

    fn f_res_add(&self) -> F {
        self.word.f_res_add()
    }

    fn f_res_mul(&self) -> F {
        self.word.f_res_mul()
    }

    fn f_pc_abs(&self) -> F {
        self.word.f_pc_abs()
    }

    fn f_pc_rel(&self) -> F {
        self.word.f_pc_rel()
    }

    fn f_pc_jnz(&self) -> F {
        self.word.f_pc_jnz()
    }

    fn f_ap_add(&self) -> F {
        self.word.f_ap_add()
    }

    fn f_ap_one(&self) -> F {
        self.word.f_ap_one()
    }

    fn f_opc_call(&self) -> F {
        self.word.f_opc_call()
    }

    fn f_opc_ret(&self) -> F {
        self.word.f_opc_ret()
    }

    fn f_opc_aeq(&self) -> F {
        self.word.f_opc_aeq()
    }

    fn f15(&self) -> F {
        self.word.f15()
    }
}

/// A data structure to store a current step of Cairo computation
pub struct CairoStep<'a, F> {
    /// state of the computation
    pub mem: &'a mut CairoMemory<F>,
    // comment instr for efficiency
    /// current pointers
    pub curr: CairoState<F>,
    /// (if any) next pointers
    pub next: Option<CairoState<F>>,
    /// state auxiliary variables
    pub vars: CairoContext<F>,
}

impl<'a, F: Field> CairoStep<'a, F> {
    /// Creates a new Cairo execution step from a step index, a Cairo word, and current pointers
    pub fn new(mem: &mut CairoMemory<F>, ptrs: CairoState<F>) -> CairoStep<'_, F> {
        CairoStep {
            mem,
            curr: ptrs,
            next: None,
            vars: CairoContext::default(),
        }
    }

    /// Executes a Cairo step from the current registers
    pub fn execute(&mut self) -> CairoInstruction<F> {
        // This order is important in order to allocate the memory in time
        self.set_op0();
        self.set_op1();
        self.set_res();
        self.set_dst();
        // If the Option<> is not a guarantee for continuation of the program, we may be removing this
        let next_pc = self.next_pc();
        let (next_ap, next_fp) = self.next_apfp();
        self.next = Some(CairoState::new(
            next_pc.expect("Empty next program counter"),
            next_ap.expect("Empty next allocation pointer"),
            next_fp.expect("Empty next frame pointer"),
        ));
        CairoInstruction::new(self.instr(), self.curr, self.vars)
    }

    /// This function returns the current word instruction being executed
    pub fn instr(&mut self) -> CairoWord<F> {
        CairoWord::new(self.mem.read(self.curr.pc).expect("pc points to None cell"))
    }

    /// This function computes the first operand address
    pub fn set_op0(&mut self) {
        let reg = match self.instr().op0_reg() {
            /*0*/ OP0_AP => self.curr.ap, // reads first word from allocated memory
            /*1*/ _ => self.curr.fp, // reads first word from input stack
        }; // no more values than 0 and 1 because op0_reg is one bit
        self.vars.adr_op0 = reg + self.instr().off_op0();
        self.vars.op0 = self.mem.read(self.vars.adr_op0);
    }

    /// This function computes the second operand address and content and the instruction size
    /// Panics if the flagset `OP1_SRC` has more than 1 nonzero bit
    pub fn set_op1(&mut self) {
        let (reg, size) = match self.instr().op1_src() {
            /*0*/
            OP1_DBL => (self.vars.op0.expect("None op0 for OP1_DBL"), F::one()), // double indexing, op0 should be positive for address
            /*1*/
            OP1_VAL => (self.curr.pc, F::from(2u32)), // off_op1 will be 1 and then op1 contains an immediate value
            /*2*/ OP1_FP => (self.curr.fp, F::one()),
            /*4*/ OP1_AP => (self.curr.ap, F::one()),
            _ => panic!("Invalid op1_src flagset"),
        };
        self.vars.size = size;
        self.vars.adr_op1 = reg + self.instr().off_op1(); // apply second offset to corresponding register
        self.vars.op1 = self.mem.read(self.vars.adr_op1);
    }

    /// This function computes the value of the result of the arithmetic operation
    /// Panics if a `jnz` instruction is used with an invalid format
    ///     or if the flagset `RES_LOG` has more than 1 nonzero bit
    pub fn set_res(&mut self) {
        if self.instr().pc_up() == PC_JNZ {
            /*4*/
            // jnz instruction
            if self.instr().res_log() == RES_ONE /*0*/
                && self.instr().opcode() == OPC_JMP_INC /*0*/
                && self.instr().ap_up() != AP_ADD
            /* not 1*/
            {
                self.vars.res = Some(F::zero()); // "unused"
            } else {
                panic!("Invalid JNZ instruction");
            }
        } else if self.instr().pc_up() == PC_SIZ /*0*/
            || self.instr().pc_up() == PC_ABS /*1*/
            || self.instr().pc_up() == PC_REL
        /*2*/
        {
            // rest of types of updates
            // common increase || absolute jump || relative jump
            match self.instr().res_log() {
                /*0*/
                RES_ONE => self.vars.res = self.vars.op1, // right part is single operand
                /*1*/
                RES_ADD => {
                    self.vars.res = Some(
                        self.vars.op0.expect("None op0 after RES_ADD")
                            + self.vars.op1.expect("None op1 after RES_ADD"),
                    )
                } // right part is addition
                /*2*/
                RES_MUL => {
                    self.vars.res = Some(
                        self.vars.op0.expect("None op0 after RES_MUL")
                            * self.vars.op1.expect("None op1 after RES_MUL"),
                    )
                } // right part is multiplication
                _ => panic!("Invalid res_log flagset"),
            }
        } else {
            // multiple bits take value 1
            panic!("Invalid pc_up flagset");
        }
    }

    /// This function computes the destination address
    pub fn set_dst(&mut self) {
        let reg = match self.instr().dst_reg() {
            /*0*/ DST_AP => self.curr.ap, // read from stack
            /*1*/ _ => self.curr.fp, // read from parameters
        }; // no more values than 0 and 1 because op0_reg is one bit
        self.vars.adr_dst = reg + self.instr().off_dst();
        self.vars.dst = self.mem.read(self.vars.adr_dst);
    }

    /// This function computes the next program counter
    /// Panics if the flagset `PC_UP` has more than 1 nonzero bit
    pub fn next_pc(&mut self) -> Option<F> {
        match self.instr().pc_up() {
            /*0*/
            PC_SIZ => Some(self.curr.pc + self.vars.size), // common case, next instruction is right after the current one
            /*1*/
            PC_ABS => Some(self.vars.res.expect("None res after PC_ABS")), // absolute jump, next instruction is in res,
            /*2*/
            PC_REL => Some(self.curr.pc + self.vars.res.expect("None res after PC_REL")), // relative jump, go to some address relative to pc
            /*4*/
            PC_JNZ => {
                // conditional relative jump (jnz)
                if self.vars.dst == Some(F::zero()) {
                    Some(self.curr.pc + self.vars.size) // if condition false, common case
                } else {
                    // if condition true, relative jump with second operand
                    Some(self.curr.pc + self.vars.op1.expect("None op1 after PC_JNZ"))
                }
            }
            _ => panic!("Invalid pc_up flagset"),
        }
    }

    /// This function computes the next values of the allocation and frame pointers
    /// Panics if in a `call` instruction the flagset [FlagSets::ap_up] is incorrect
    ///     or if in any other instruction the flagset [FlagSets::ap_up] has more than 1 nonzero bit
    ///     or if the flagset `OPCODE` has more than 1 nonzero bit
    fn next_apfp(&mut self) -> (Option<F>, Option<F>) {
        let (next_ap, next_fp);
        // The following branches don't include the assertions. That is done in the verification.
        if self.instr().opcode() == OPC_CALL {
            /*1*/
            // "call" instruction
            self.mem.write(self.curr.ap, self.curr.fp); // Save current fp
            self.vars.dst = self.mem.read(self.curr.ap); // update dst content
            self.mem
                .write(self.curr.ap + F::one(), self.curr.pc + self.vars.size); // Save next instruction
            self.vars.op0 = self.mem.read(self.curr.ap + F::one()); //update op0 content

            // Update fp
            next_fp = Some(self.curr.ap + F::from(2u32)); // pointer for next frame is after current fp and instruction after call
                                                          // Update ap
            match self.instr().ap_up() {
                /*0*/
                AP_Z2 => next_ap = Some(self.curr.ap + F::from(2u32)), // two words were written so advance 2 positions
                _ => panic!("ap increment in call instruction"), // ap increments not allowed in call instructions
            };
        } else if self.instr().opcode() == OPC_JMP_INC /*0*/
            || self.instr().opcode() == OPC_RET /*2*/
            || self.instr().opcode() == OPC_AEQ
        /*4*/
        {
            // rest of types of instruction
            // jumps and increments || return || assert equal
            match self.instr().ap_up() {
                /*0*/ AP_Z2 => next_ap = Some(self.curr.ap), // no modification on ap
                /*1*/
                AP_ADD => {
                    // ap += <op> should be larger than current ap
                    next_ap = Some(self.curr.ap + self.vars.res.expect("None res after AP_ADD"))
                }
                /*2*/ AP_ONE => next_ap = Some(self.curr.ap + F::one()), // ap++
                _ => panic!("Invalid ap_up flagset"),
            }

            match self.instr().opcode() {
                /*0*/
                OPC_JMP_INC => next_fp = Some(self.curr.fp), // no modification on fp
                /*2*/
                OPC_RET => next_fp = Some(self.vars.dst.expect("None dst after OPC_RET")), // ret sets fp to previous fp that was in [ap-2]
                /*4*/
                OPC_AEQ => {
                    // The following conditional is a fix that is not explained in the whitepaper
                    // The goal is to distinguish two types of ASSERT_EQUAL where one checks that
                    // dst = res , but in order for this to be true, one sometimes needs to write
                    // the res in mem(adr_dst) and sometimes write dst in mem(res_dir). The only
                    // case where res can be None is when res = op1 and thus res_dir = adr_op1
                    if self.vars.res.is_none() {
                        // res = dst
                        self.mem.write(
                            self.vars.adr_op1,
                            self.vars.dst.expect("None dst after OPC_AEQ"),
                        );
                        // update the value of the variable as well
                        self.vars.op1 = self.mem.read(self.vars.adr_op1);
                        self.vars.res = self.mem.read(self.vars.adr_op1);
                    } else {
                        // dst = res
                        self.mem.write(
                            self.vars.adr_dst,
                            self.vars.res.expect("None res after OPC_AEQ"),
                        );
                        // update the value of the variable as well
                        self.vars.dst = self.mem.read(self.vars.adr_dst);
                    }
                    next_fp = Some(self.curr.fp); // no modification on fp
                }
                _ => {
                    panic!("This case must never happen")
                }
            }
        } else {
            panic!("Invalid opcode flagset");
        }
        (next_ap, next_fp)
    }
}

/// This struct stores the needed information to run a program
pub struct CairoProgram<'a, F> {
    /// total number of steps
    pub steps: F,
    /// full execution memory
    pub mem: &'a mut CairoMemory<F>,
    /// initial computation registers
    pub ini: CairoState<F>,
    /// final computation pointers
    pub fin: CairoState<F>,
    /// execution trace as a vector of [CairoInstruction]
    pub trace: Vec<CairoInstruction<F>>,
}

impl<'a, F: Field> CairoProgram<'a, F> {
    /// Creates a Cairo execution from the public information (memory and initial pointers)
    pub fn new(mem: &mut CairoMemory<F>, pc: u64) -> CairoProgram<'_, F> {
        let ap = mem.len();
        let mut prog = CairoProgram {
            steps: F::zero(),
            mem,
            ini: CairoState::new(F::from(pc), F::from(ap), F::from(ap)),
            fin: CairoState::new(F::zero(), F::zero(), F::zero()),
            trace: Vec::new(),
        };
        prog.execute();
        prog
    }

    /// Outputs the total number of steps of the execution carried out by the runner
    pub fn steps(&self) -> F {
        self.steps
    }

    /// Outputs the initial value of the pointers after the execution carried out by the runner
    pub fn ini(&self) -> CairoState<F> {
        self.ini
    }

    /// Outputs the final value of the pointers after the execution carried out by the runner
    pub fn fin(&self) -> CairoState<F> {
        self.fin
    }

    /// Returns a reference to the set of instructions
    pub fn trace(&self) -> &Vec<CairoInstruction<F>> {
        &self.trace
    }

    /// This function simulates an execution of the Cairo program received as input.
    /// It generates the full memory stack and the execution trace
    fn execute(&mut self) {
        // set finishing flag to false, as it just started
        let mut end = false;
        // saves local copy of the initial (claimed) pointers of the program
        let mut curr = self.ini;
        let mut next = self.ini;
        // first timestamp
        let mut n: u64 = 0;
        // keep executing steps until the end is reached
        while !end {
            // create current step of computation
            let mut step = CairoStep::new(self.mem, next);
            // save current value of the pointers
            curr = step.curr;
            // execute current step and increase time counter
            let instr = step.execute();
            self.trace.push(instr);
            n += 1;
            match step.next {
                None => end = true, // if find no next pointers, end
                _ => {
                    // if there are next pointers
                    end = false;
                    // update next value of pointers
                    next = step.next.expect("Empty next pointers");
                    if curr.ap <= next.pc {
                        // if reading from unallocated memory, end
                        end = true;
                    }
                }
            }
        }
        self.steps = F::from(n);
        self.fin = CairoState::new(curr.pc, curr.ap, curr.fp);
    }
}
