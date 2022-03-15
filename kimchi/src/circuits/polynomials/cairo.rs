//!This implements the verification of a Cairo execution trace
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
//!
//! The Kimchi 15 columns could be:
//! GateType  CairoInstruction Zero  (...)              CairoTransition   (...)              Zero   CairoClaim     CairoMem?
//!    row   ->   0         1          2          ...   2n                     2n+1  ......  3n -1       3n
//!     0    ·    pc        fPC_ABS    (next) pc        pc\[i\]           (c)  pc\[i+2\] ... pc\[2n-2\]  pc\[0\] (c)
//!     1    ·    ap        fPC_REL    (next) ap  ...   ap\[i\]           (c)  ap\[i+2\] ... ap\[2n-2\]  ap\[0\] (c)
//!  c  2    ·    fp        fPC_JNZ    (next) fp        fp\[i\]           (c)  fp\[i+2\] ... fp\[2n-2\]  fp\[0\] (c)
//!  o  3    ·    size      fAP_ADD        .            size\[i\]         (c)    .              .        pc\[2n-2\] (c)
//!  l  4    ·    res       fAP_ONE        .            res\[i\]          (c)    .              .        ap\[2n-2\] (c)
//!  |  5    ·    dst       fOPC_CALL      .            dst\[i\]          (c)    .              .        pc_ini
//!  v  6    ·    op1       fOPC_RET                    op1\[i\]          (c)    .              .        ap_ini
//!     7         op0       fOPC_AEQ                    fPC_ABS\[i+1\]    (c)                            pc_fin
//!     8         off_dst   fDST_FP                     fPC_REL\[i+1\]    (c)                            ap_fin
//!     9         off_op1   fOP0_FP                     fPC_JNZ\[i+1\]    (c)                         
//!     10        off_op0   fOP1_VAL                    fAP_ADD\[i+1\]    (c)                         
//!     11        adr_dst   fOP1_FP                     fAP_ONE\[i+1\]    (c)                         
//!     12        adr_op1   fOP1_AP                     fOPC_CALL\[i+1\]  (c)
//!     13        adr_op0   fRES_ADD                    fOPC_RET\[i+1\]   (c)
//!     14        instr     fRES_MUL                    

//use std::fmt::{Display, Formatter};

use std::marker::PhantomData;

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::expr::{witness_curr, witness_next, Cache, ConstantExpr, Expr, E};
use crate::circuits::gate::GateType;
//use crate::circuits::wires::COLUMNS;
use ark_ff::{FftField, Field, One}; //, PrimeField};

const NUM_FLAGS: usize = 16;

/// Returns the expression corresponding to the literal "2"
fn two<F: Field>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u16.into())) // 2
}

/// Combines the constraints for the Cairo gates
pub fn gate_combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    Instruction::combined_constraints(alphas)
        + Transition::combined_constraints(alphas)
        + Claim::combined_constraints(alphas)
        + E::literal(F::zero())
}

/// Combines the constraints for the Cairo gates depending on its type
pub fn circuit_gate_combined_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::CairoInstruction => Instruction::combined_constraints(alphas),
        GateType::CairoTransition => Transition::combined_constraints(alphas),
        GateType::CairoClaim => Claim::combined_constraints(alphas),
        GateType::Zero => E::literal(F::zero()),
        _ => panic!("invalid gate type"),
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
        // This unnatural ordering of the flags is meant to allow copies (first 7 columns)
        let f_pc_abs = witness_next(0);
        let f_pc_rel = witness_next(1);
        let f_pc_jnz = witness_next(2);
        let f_ap_inc = witness_next(3);
        let f_ap_one = witness_next(4);
        let f_opc_call = witness_next(5);
        let f_opc_ret = witness_next(6);
        let f_opc_aeq = witness_next(7);
        let f_dst_fp = witness_next(8);
        let f_op0_fp = witness_next(9);
        let f_op1_val = witness_next(10);
        let f_op1_fp = witness_next(11);
        let f_op1_ap = witness_next(12);
        let f_res_add = witness_next(13);
        let f_res_mul = witness_next(14);
        // rotate flags to its natural ordering
        let mut flags: Vec<Expr<ConstantExpr<F>>> =
            (0..NUM_FLAGS - 1).map(|i| witness_next(i)).collect();
        flags.rotate_right(7);

        // LIST OF CONSTRAINTS
        // -------------------
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![];
        let mut cache = Cache::default();

        // INSTRUCTIONS RELATED

        // Redundant if we perform the instruction well formness check
        // * Check last flag is always zero
        // f15 == 0
        // let f15 = wit(<idx>);
        // constraints = vec![f15];

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
        let ap_up = cache.cache(f_ap_one + f_ap_inc);
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

pub struct Transition<F>(PhantomData<F>);

impl<F> Argument<F> for Transition<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoTransition);
    const CONSTRAINTS: u32 = 4;

    /// Generates the constraints for the Cairo transition
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        let pc = witness_curr(0);
        let ap = witness_curr(1);
        let fp = witness_curr(2);
        let size = witness_curr(3);
        let res = witness_curr(4);
        let dst = witness_curr(5);
        let op1 = witness_curr(6);
        let f_pc_abs = witness_curr(7);
        let f_pc_rel = witness_curr(8);
        let f_pc_jnz = witness_curr(9);
        let f_ap_inc = witness_curr(10);
        let f_ap_one = witness_curr(11);
        let f_opc_call = witness_curr(12);
        let f_opc_ret = witness_curr(13);
        let next_pc = witness_next(0);
        let next_ap = witness_next(1);
        let next_fp = witness_next(2);

        // LIST OF CONSTRAINTS
        // -------------------
        // REGISTERS-RELATED
        // * Check next allocation pointer
        //  next_ap =
        //             ap +
        //  if ap_up == 1  : res
        //  if ap_up == 2  : 1
        // if opcode == 1  : 2
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![
            next_ap
                - (ap.clone() + f_ap_inc * res.clone() + f_ap_one + f_opc_call.clone().double()),
        ];

        // * Check next frame pointer
        constraints.push(
            next_fp                                                                   //             next_fp =
                        - (f_opc_call.clone() * (ap + two())                          // if opcode == 1      : ap + 2
                        + f_opc_ret.clone() * dst.clone()                                     // if opcode == 2      : dst
                        + (E::one() - f_opc_call - f_opc_ret) * fp ), // if opcode == 4 or 0 : fp
        );

        // * Check next program counter (pc update)
        constraints.push(
            f_pc_jnz.clone()
                * (dst.clone() * res.clone() - E::one())
                * (next_pc.clone() - (pc.clone() - size.clone())),
        ); // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
        constraints.push(
            f_pc_jnz.clone() * dst * (next_pc.clone() - (pc.clone() + op1))                         // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
                    + (E::one() - f_pc_jnz.clone()) * next_pc                                                       // <=> pc_up = {0,1,2}        : next_pc = ... // not a conditional jump
                        - (E::one() - f_pc_abs.clone() - f_pc_rel.clone() - f_pc_jnz) * (pc.clone() + size) // <=> pc_up = 0              : next_pc = pc + size // common case
                        - f_pc_abs * res.clone()                                                                    // <=> pc_up = 1              : next_pc = res       // absolute jump
                        - f_pc_rel * (pc + res), //                                                    <=> pc_up = 2              : next_pc = pc + res  // relative jump
        );
        constraints
    }
}

pub struct Claim<F>(PhantomData<F>);

impl<F> Argument<F> for Claim<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoClaim);
    const CONSTRAINTS: u32 = 5;

    /// Generates the constraints for the Cairo claim
    ///     Accesses Curr row only
    fn constraints() -> Vec<E<F>> {
        let pc0 = witness_curr(0);
        let ap0 = witness_curr(1);
        let fp0 = witness_curr(2);
        let pc_t = witness_curr(3);
        let ap_t = witness_curr(4);
        let pc_ini = witness_curr(5);
        let ap_ini = witness_curr(6);
        let pc_fin = witness_curr(7);
        let ap_fin = witness_curr(8);

        // LIST OF CONSTRAINTS
        // * Check initial and final ap, fp, pc
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![ap0 - ap_ini.clone()]; // ap0 = ini_ap
        constraints.push(fp0 - ap_ini); // fp0 = ini_ap
        constraints.push(ap_t - ap_fin); // apT = fin_ap
        constraints.push(pc0 - pc_ini); // pc0 = ini_pc
        constraints.push(pc_t - pc_fin); // pcT = fin_pc

        constraints
    }
}

pub struct Stack<F>(PhantomData<F>);

impl<F> Argument<F> for Stack<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoStack);
    const CONSTRAINTS: u32 = 5;

    /// Generates the constraints for the Cairo claim
    ///     Accesses Curr row only
    fn constraints() -> Vec<E<F>> {
        let pc0 = witness_curr(0);
        let ap0 = witness_curr(1);
        let fp0 = witness_curr(2);
        let pc_t = witness_curr(3);
        let ap_t = witness_curr(4);
        let pc_ini = witness_curr(5);
        let ap_ini = witness_curr(6);
        let pc_fin = witness_curr(7);
        let ap_fin = witness_curr(8);

        // LIST OF CONSTRAINTS
        // * Check initial and final ap, fp, pc
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![ap0 - ap_ini.clone()]; // ap0 = ini_ap
        constraints.push(fp0 - ap_ini); // fp0 = ini_ap
        constraints.push(ap_t - ap_fin); // apT = fin_ap
        constraints.push(pc0 - pc_ini); // pc0 = ini_pc
        constraints.push(pc_t - pc_fin); // pcT = fin_pc

        constraints
    }
}

/*
    // MEMORY-RELATED

    // * Memory checks: continuity and single value

    // * Memory permutation check

    // * PLONK's copy constraints??

    //v(Column::Index(GateType::Cairo)) * E::combine_constraints(alpha0, constraints)

*/
