//!This implements the constraints of the Cairo gates

//use std::fmt::{Display, Formatter};

use std::marker::PhantomData;

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr::{self, Column};
use crate::circuits::expr::{witness_curr, witness_next, Cache, ConstantExpr, Expr, E};
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::scalars::ProofEvaluations;
use crate::circuits::wires::{GateWires, Wire, NEW_COLS};
use ark_ff::{FftField, Field, One};
use array_init::array_init;
use cairo::{
    runner::{CairoInstruction, CairoProgram, Pointers, ACC_PER_INS},
    word::{FlagBits, Offsets},
};
use rand::prelude::StdRng;
use rand::SeedableRng;

const NUM_FLAGS: usize = 16;
pub const CIRCUIT_GATE_COUNT: usize = 3;

// Constants for column indexing of CairoInstruction gate
const COL_PC: usize = 0;
const COL_AP: usize = 1;
const COL_FP: usize = 2;
const COL_INSTR: usize = 3;
const COL_PERM: usize = 4;
const COL_SIZE: usize = 5;
const COL_RES: usize = 6;
const COL_DST: usize = 7;
const COL_OP0: usize = 8;
const COL_OP1: usize = 9;
const COL_OFF_DST: usize = 10;
const COL_OFF_OP0: usize = 11;
const COL_OFF_OP1: usize = 12;
const COL_ADR_DST: usize = 13;
const COL_ADR_OP0: usize = 14;
const COL_ADR_OP1: usize = 15;
const COL_F_DST_FP: usize = 16;
const COL_F_OP0_FP: usize = 17;
const COL_F_OP1_VAL: usize = 18;
const COL_F_OP1_FP: usize = 19;
const COL_F_OP1_AP: usize = 20;
const COL_F_RES_ADD: usize = 21;
const COL_F_RES_MUL: usize = 22;
const COL_F_PC_ABS: usize = 23;
const COL_F_PC_REL: usize = 24;
const COL_F_PC_JNZ: usize = 25;
const COL_F_AP_ADD: usize = 26;
const COL_F_AP_ONE: usize = 27;
const COL_F_OPC_CALL: usize = 28;
const COL_F_OPC_RET: usize = 29;
const COL_F_OPC_AEQ: usize = 30;
const COL_F_15: usize = 31;
const COL_MEM: [usize; ACC_PER_INS] = [32, 33, 34, 35];
const COL_VAL: [usize; ACC_PER_INS] = [36, 37, 38, 39];

// GATE-RELATED

fn gate_type_to_selector<F: FftField>(typ: GateType) -> [F; CIRCUIT_GATE_COUNT] {
    match typ {
        GateType::CairoInstruction => [F::one(), F::zero(), F::zero()],
        GateType::CairoTransition => [F::zero(), F::one(), F::zero()],
        GateType::CairoClaim => [F::zero(), F::zero(), F::one()],
        _ => [F::zero(); CIRCUIT_GATE_COUNT],
    }
}

/*
pub fn view_witness<F: Field>(witness: &[Vec<F>; NEW_COLS]) {
    let rows = witness[0].len();
    for i in 0..rows {
        print!("row {}: [", i);
        for j in 0..witness.len() {
            print!("{} , ", witness[j][i].to_u64());
        }
        println!("]");
    }
}

fn view_table<F: Field>(table: &Vec<[F; NEW_COLS]>) {
    let rows = table.len();
    for i in 0..rows {
        print!("row {}: [", i);
        for j in 0..NEW_COLS {
            print!("{} , ", table[i][j].to_u64());
        }
        println!("]");
    }
}
*/

/// Returns the witness of an execution of a Cairo program in CircuitGate format
pub fn cairo_witness<F: Field>(prog: &CairoProgram<F>) -> [Vec<F>; NEW_COLS] {
    // 2 row per instruction for CairoInstruction gate
    // 1 row per instruction for CairoTransition gate
    // final row for CairoClaim gate
    let n = prog.trace().len();
    let rows = n + 1;
    let mut table: Vec<[F; NEW_COLS]> = Vec::new();
    table.resize(rows, [F::zero(); NEW_COLS]);
    for (i, inst) in prog.trace().iter().enumerate() {
        table[i] = instruction_witness(inst, prog.addresses(i), prog.values(i));
    }
    let perm = table[rows - 2][COL_PERM];
    table[rows - 1] = claim_witness(prog, perm);

    let mut witness: [Vec<F>; NEW_COLS] = array_init(|_| Default::default());
    for col in 0..NEW_COLS {
        // initialize column with zeroes
        witness[col].resize(table.len(), F::zero());
        for (row, wit) in table.iter().enumerate() {
            witness[col][row] = wit[col];
        }
    }
    witness
}

fn instruction_witness<F: Field>(
    inst: &CairoInstruction<F>,  // current instruction
    addresses: [F; ACC_PER_INS], // sorted addresses for this instruction
    values: [F; ACC_PER_INS],    // sorted values for this instruction
) -> [F; NEW_COLS] {
    let mut row: [F; NEW_COLS] = array_init(|_| F::zero());
    row[COL_PC] = inst.pc();
    row[COL_AP] = inst.ap();
    row[COL_FP] = inst.fp();
    row[COL_INSTR] = inst.instr();
    row[COL_SIZE] = inst.size();
    row[COL_RES] = inst.res();
    row[COL_DST] = inst.dst();
    row[COL_OP0] = inst.op0();
    row[COL_OP1] = inst.op1();
    row[COL_OFF_DST] = inst.off_dst();
    row[COL_OFF_OP0] = inst.off_op0();
    row[COL_OFF_OP1] = inst.off_op1();
    row[COL_ADR_DST] = inst.adr_dst();
    row[COL_ADR_OP0] = inst.adr_op0();
    row[COL_ADR_OP1] = inst.adr_op1();
    row[COL_F_15] = inst.f15();
    row[COL_F_OPC_AEQ] = inst.f_opc_aeq();
    row[COL_F_OPC_RET] = inst.f_opc_ret();
    row[COL_F_OPC_CALL] = inst.f_opc_call();
    row[COL_F_AP_ONE] = inst.f_ap_one();
    row[COL_F_AP_ADD] = inst.f_ap_add();
    row[COL_F_PC_JNZ] = inst.f_pc_jnz();
    row[COL_F_PC_REL] = inst.f_pc_rel();
    row[COL_F_PC_ABS] = inst.f_pc_abs();
    row[COL_F_RES_MUL] = inst.f_res_mul();
    row[COL_F_RES_ADD] = inst.f_res_add();
    row[COL_F_RES_ADD] = inst.f_op1_ap();
    row[COL_F_OP1_FP] = inst.f_op1_fp();
    row[COL_F_OP1_VAL] = inst.f_op1_val();
    row[COL_F_OP0_FP] = inst.f_op0_fp();
    row[COL_F_DST_FP] = inst.f_dst_fp();
    for i in 0..ACC_PER_INS {
        row[COL_MEM[i]] = addresses[i];
        row[COL_VAL[i]] = values[i];
    }
    // TODO: compute partial permutation
    row
}

fn claim_witness<F: Field>(prog: &CairoProgram<F>, perm: F) -> [F; NEW_COLS] {
    let first = 0;
    let last = prog.trace().len() - 1;
    let mut row: [F; NEW_COLS] = array_init(|_| F::zero());

    row[0] = perm;
    row[0] = prog.trace()[first].pc();
    row[1] = prog.trace()[first].ap();
    row[2] = prog.trace()[first].fp();
    row[3] = prog.trace()[last].pc();
    row[4] = prog.trace()[last].ap();
    row[5] = prog.ini().pc();
    row[6] = prog.ini().ap();
    row[7] = prog.fin().pc();
    row[8] = prog.fin().ap();
    row
}

impl<F: FftField> CircuitGate<F> {
    /// This function creates a 2-row CairoInstruction gate
    pub fn create_cairo_instruction(wires: &[GateWires; 2]) -> Vec<Self> {
        vec![
            CircuitGate {
                typ: GateType::CairoInstruction,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::Zero, // So that it ignores even rows
                wires: wires[1],
                coeffs: vec![],
            },
        ]
    }

    /// This function creates a CairoTransition gate
    pub fn create_cairo_transition(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoTransition,
            wires,
            coeffs: vec![],
        }
    }

    /// This function creates a single row CairoClaim gate
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
        for i in 0..num {
            let wire0 = Wire::new(row + 2 * i);
            let wire1 = Wire::new(row + 2 * i + 1);
            gates.extend(
                CircuitGate::create_cairo_instruction(&[wire0, wire1])
                    .iter()
                    .cloned(),
            );
        }
        // n-1 CairoTransition gates
        for i in 0..num - 1 {
            gates.push(CircuitGate::create_cairo_transition(Wire::new(
                row + 2 * num + i,
            )));
        }
        // the final one is considered a Zero gate
        gates.push(CircuitGate::zero(Wire::new(row + 3 * num - 1)));
        gates.push(CircuitGate::create_cairo_claim(Wire::new(row + 3 * num)));

        gates
    }

    /// verifies that the Cairo gate constraints are solved by the witness depending on its type
    pub fn verify_cairo_gate(
        &self,
        row: usize,
        witness: &[Vec<F>; NEW_COLS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let curr: [F; NEW_COLS] = array_init(|i| witness[i][row]);
        let mut next: [F; NEW_COLS] = array_init(|_| F::zero());
        if self.typ != GateType::CairoClaim {
            next = array_init(|i| witness[i][row + 1]);
        }

        // column polynomials
        let polys = {
            let mut h = std::collections::HashSet::new();
            for i in 0..NEW_COLS {
                h.insert(Column::Witness(i)); // column witness polynomials
            }
            // gate selector polynomials
            h.insert(Column::Index(GateType::CairoInstruction));
            h.insert(Column::Index(GateType::CairoClaim));
            h.insert(Column::Index(GateType::Zero));
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
        witness: &[Vec<F>; NEW_COLS],
        //_cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let this: [F; NEW_COLS] = array_init(|i| witness[i][row]);

        match self.typ {
            GateType::Zero => Ok(()),
            GateType::CairoInstruction => {
                let next: [F; NEW_COLS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_instruction(&this, &next)
            }
            GateType::CairoClaim => CircuitGate::ensure_claim(&this),
            // TODO(querolita): memory related checks
            _ => Err(
                "Incorrect GateType: expected CairoInstruction, CairoTransition, or CairoClaim"
                    .to_string(),
            ),
        }
    }

    fn ensure_instruction(curr: &[F], next: &[F]) -> Result<(), String> {
        let pc = curr[COL_PC];
        let ap = curr[COL_AP];
        let fp = curr[COL_FP];
        let instr = curr[COL_INSTR];
        //let perm = curr[COL_PERM];
        let size = curr[COL_SIZE];
        let res = curr[COL_RES];
        let dst = curr[COL_DST];
        let op0 = curr[COL_OP0];
        let op1 = curr[COL_OP1];
        let off_dst = curr[COL_OFF_DST];
        let off_op0 = curr[COL_OFF_OP0];
        let off_op1 = curr[COL_OFF_OP1];
        let adr_dst = curr[COL_ADR_DST];
        let adr_op0 = curr[COL_ADR_OP0];
        let adr_op1 = curr[COL_ADR_OP1];

        let f15 = curr[COL_F_15];
        let f_opc_aeq = curr[COL_F_OPC_AEQ];
        let f_opc_ret = curr[COL_F_OPC_RET];
        let f_opc_call = curr[COL_F_OPC_CALL];
        let f_ap_one = curr[COL_F_AP_ONE];
        let f_ap_add = curr[COL_F_AP_ADD];
        let f_pc_jnz = curr[COL_F_PC_JNZ];
        let f_pc_rel = curr[COL_F_PC_REL];
        let f_pc_abs = curr[COL_F_PC_ABS];
        let f_res_mul = curr[COL_F_RES_MUL];
        let f_res_add = curr[COL_F_RES_ADD];
        let f_op1_ap = curr[COL_F_OP1_AP];
        let f_op1_fp = curr[COL_F_OP1_FP];
        let f_op1_val = curr[COL_F_OP1_VAL];
        let f_op0_fp = curr[COL_F_OP0_FP];
        let f_dst_fp = curr[COL_F_DST_FP];

        let mem: Vec<F> = (0..ACC_PER_INS).map(|i| curr[COL_MEM[i]]).collect();
        let val: Vec<F> = (0..ACC_PER_INS).map(|i| curr[COL_VAL[i]]).collect();
        //let perm = curr[COL_PERM];

        let next_pc = next[COL_PC];
        let next_ap = next[COL_AP];
        let next_fp = next[COL_FP];
        //let next_perm = next[COL_PERM];
        let next_mem = next[COL_MEM[0]];
        let next_val = next[COL_VAL[1]];

        let zero = F::zero();
        let one = F::one();
        let two = F::from(2u16);

        // FLAGS RELATED

        // check last flag is a zero
        // f15 == 0
        ensure_eq!(zero, f15, "last flag is nonzero");

        // check booleanity of flags
        // fi * (1-fi) == 0 for i=[0..15)
        let flags: Vec<F> = (COL_F_DST_FP..COL_F_15).map(|i| curr[i]).collect();
        for &flag in &flags {
            ensure_eq!(zero, flag * (one - flag), "non-boolean flags");
        }

        // well formness of instruction
        let shape = {
            let shift = F::from(2u32.pow(15)); // 2^15;
            let pow16 = shift.double(); // 2^16
            let dst_sft = off_dst + shift;
            let op0_sft = off_op0 + shift;
            let op1_sft = off_op1 + shift;
            // recompose instruction as: flags[15..0] | op1_sft | op0_sft | dst_sft
            let mut aux = flags[NUM_FLAGS - 1];
            for i in (0..NUM_FLAGS - 1).rev() {
                aux = aux * two + flags[i];
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
        let ap_set = f_ap_one + f_ap_add;
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

        // TRANSITION RELATED
        // ------------------

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(
            next_ap, //               next_ap =
            ap                   //             ap +
            + f_ap_add * res      //  if ap_up == 1 : res
            + f_ap_one           //  if ap_up == 2 : 1
            + f_opc_call.double(), // if opcode == 1 : 2
            "wrong next allocation pointer"
        );

        // * Check next frame pointer
        ensure_eq!(
            next_fp, //                                       next_fp =
            f_opc_call * (ap + two)      // if opcode == 1      : ap + 2
            + f_opc_ret * dst                    // if opcode == 2      : dst
            + (one - f_opc_call - f_opc_ret) * fp, // if opcode == 4 or 0 : fp
            "wrong next frame pointer"
        );

        //TODO(querolita): check if these ensure_eq are correct

        // * Check next program counter
        ensure_eq!(
            zero,
            f_pc_jnz * (dst * res - one) * (next_pc - (pc - size)), // <=> pc_up = 4 and dst = 0 : next_pc = pc + size // no jump
            "wrong next program counter"
        );
        ensure_eq!(
            zero,
            f_pc_jnz * dst * (next_pc - (pc + op1))                  // <=> pc_up = 4 and dst != 0 : next_pc = pc + op1  // condition holds
            + (one - f_pc_jnz) * next_pc                             // <=> pc_up = {0,1,2} : next_pc = ... // not a conditional jump
                - (one - f_pc_abs - f_pc_rel - f_pc_jnz) * (pc + size) // <=> pc_up = 0 : next_pc = pc + size // common case
                - f_pc_abs * res                                     // <=> pc_up = 1 : next_pc = res       // absolute jump
                - f_pc_rel * (pc + res), //                             <=> pc_up = 2 : next_pc = pc + res  // relative jump
            "wrong next program counter"
        );

        // MEMORY RELATED
        // Singularity and continuity of the memory
        for i in 0..ACC_PER_INS {
            let (nextmem, nextval) = {
                if i != ACC_PER_INS - 1 {
                    (mem[i + 1], val[i + 1])
                } else {
                    (next_mem, next_val)
                }
            };
            // Continuity
            // (a'_i+1 - a'_i)(a'_i+1 - a'_i - 1)
            ensure_eq!(
                zero,
                (nextmem - mem[i]) * (nextmem - mem[i] - one),
                "Memory has holes"
            );
            // Singularity
            // (v'_i+1 - v'_i)(a'_i+1 - a'_i - 1)
            ensure_eq!(
                zero,
                (nextval - val[i]) * (nextmem - mem[i] - one),
                "Values have changed"
            );
        }

        Ok(())
    }

    fn ensure_claim(claim: &[F]) -> Result<(), String> {
        let pc0 = claim[0];
        let ap0 = claim[1];
        let fp0 = claim[2];
        let pc_t = claim[3];
        let ap_t = claim[4];
        let pc_ini = claim[5];
        let ap_ini = claim[6];
        let pc_fin = claim[7];
        let ap_fin = claim[8];

        let zero = F::zero();
        // * Check initial and final ap, fp, pc
        ensure_eq!(zero, ap0 - ap_ini, "wrong initial ap"); // ap0 = ini_ap
        ensure_eq!(zero, fp0 - ap_ini, "wrong initial fp"); // fp0 = ini_ap
        ensure_eq!(zero, ap_t - ap_fin, "wrong final ap"); // apT = fin_ap
        ensure_eq!(zero, pc0 - pc_ini, "wrong initial pc"); // pc0 = ini_pc
        ensure_eq!(zero, pc_t - pc_fin, "wrong final pc"); // pcT = fin_pc

        Ok(())
    }
}

/// Returns the expression corresponding to the literal "2"
fn two<F: Field>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u16.into())) // 2
}

/// Combines the constraints for the Cairo gates
pub fn gate_combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    Instruction::combined_constraints(alphas)
        + Claim::combined_constraints(alphas)
        + E::literal(F::zero())
}

/// Combines the constraints for the Cairo gates depending on its type
pub fn circuit_gate_combined_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::CairoInstruction => Instruction::combined_constraints(alphas),
        GateType::CairoClaim => Claim::combined_constraints(alphas),
        GateType::Zero => E::literal(F::zero()),
        _ => panic!("invalid gate type"),
    }
}

// -------------------
// CONSTRAINTS SECTION
// -------------------

//~ Cairo programs can have the following assembly-like instructions:
//~ - Memory access: \[x\]
//~ - Assert equal: <left_hand_op> = <right_hand_op>
//~ · val
//~ · \[reg1 + off_op1\]
//~ · \[reg0 + off_op0\] +|* \[reg1 + off_op1\]
//~ · \[reg0 + off_op0\] +|* val
//~ · \[\[reg0 + off_op0\] + off_op1\]
//~ - Jumps
//~ · jmp abs <address>     // unconditional absolute jump
//~ · jmp rel <offset>      // unconditional relative jump
//~ · jmp rel <offset> if <op> != 0    // conditional jump
//~ - Functions
//~ · call abs <address>    // calls a function (absolute location)
//~ · call rel <offset>     // calls a function (relative location)
//~ · ret                   // returns to execution after the call
//~ - Increments
//~ · ap += <op>
//~ · ap++
//~
//~ A Cairo program runs accross a number of state transitions.
//~ Each state transition has the following structure:
//~
//~ * Has access to a read-only memory
//~ * Input: 3 types of registers
//~  - pc (= program counter):  address of current instruction
//~  - ap (= allocation pointer): first free memory address
//~  - fp (= frame pointer): beginning of stack (for function arguments)
//~ * Output:
//~  - next_pc: address of next instruction
//~  - next_ap: address of next free memory slot
//~  - next_fp: pointer to stack (can remain the same as fp)
//~
//~Cairo words are field elements of characteristic > 2^64
//~Cairo instructions are stored as words (63 or 64 bits - actual instruction or immediate value)
//~Instructions with immediate values are stored in 2 words
//~- The first word stores instruction
//~- The second word stores the value
//~Words of instructions consist of
//~* 3 signed offsets of 16 bits each, in the range [-2^15,2^15) biased representation
//~ - off_dst (= offset from destination address): used to compute address of assignment
//~ - off_op0 (= offset from first operand): used to compute address of first operand in instruction
//~ - off_op1 (= offset from second operand): used to compute address of second operand in instruction
//~* 15 bits of flags divided into 7 groups
//~  When multiple bits, at most one can be 1 and the rest must be 0
//~ - dst_reg \[0\] = fDST_REG : indicates what pointer off_dst refers to ( 0 => ap , 1 => fp )
//~ - op0_reg \[1\] = fOP0_REG : indicates what pointer off_op0 refers to ( 0 => ap , 1 => fp )
//~ - op1_src \[2..4\] : encodes the type of second operand
//~  · 0: indicates off_op1 is b in the double indexing \[\[ point + a \] + b \]
//~  · 1: indicates off_op1 is an immediate value = fOP1_VAL = 1
//~  · 2: indicates offset off_op1 relative to fp = fOP1_FP = 1
//~  · 4: indicates offset off_op1 relative to ap = fOP1_AP = 1
//~ - res_logic \[5..6\]: defines (if any) arithmetic operation in right part
//~  · 0: right part is single operand
//~  · 1: right part is addition = fRES_ADD = 1
//~  · 2: right part is multiplication = fRES_MUL = 1
//~ - pc_update \[7..9\]: defines the type of update for the pc
//~  · 0 = regular increase by size of current instruction
//~  · 1 = absolute jump to res address = fPC_ABS_JMP = 1
//~  · 2 = relative jump of step res = fPC_REL_JMP = 1
//~  · 4 = conditional jump (jnz) with step in op1 = fPC_JNZ = 1
//~ - ap_update \[10..11\]: defines the type of update for the ap
//~  · 0: means the new ap is the same, same free position
//~  · 1: means there is an ap+=<op> instruction = fAP_INC = 1
//~  · 2: means there is an ap++ instruction = fAP_ADD1 = 1
//~ - opcode \[12..14\]: encodes type of assembly instruction
//~  · 0: jumps or increments instruction
//~  · 1: call instruction = fOPC_CALL = 1
//~  · 2: return instruction = fOPC_RET = 1
//~  · 4: assert equal instruction (assignment to value or check equality) = fOPC_ASSEQ = 1
//~* in little-endian form = leftmost least significant bit
//~
//~The transition function uses 4 auxiliary values:
//~- dst: left part of instruction, destination
//~- op0: content of first operand of right part
//~- op1: content of second operand of right part
//~- res: result of the operation in the right part
//~
//~ The Kimchi 15 columns could be:
//~ GateType  CairoInstruction  (...)     Zero        CairoClaim
//~    row   ->   0         1             n-1         n
//~  c  0©        pc        (next) pc     pc\[n-1\]   perm\[n-1\] (c)
//~  o  1©        ap        (next) ap     ap\[n-1\]   pc\[0\] (c)
//~  l  2©        fp        (next) fp     fp\[n-1\]   ap\[0\] (c)
//~  |  3©  pub   instr                               fp\[0\] (c)
//~  v  4©        perm                                pc\[n-1\] (c)
//~     5©        size                 .              ap\[n-1\] (c)
//~     6         res                  .              pc_ini  (pub)
//~     7         dst                  .              ap_ini  (pub)
//~     8         op0                                 pc_fin  (pub)
//~     9         op1                                 ap_fin  (pub)
//~     10        off_dst
//~     11        off_op0
//~     12        off_op1
//~     13        adr_dst
//~     14        adr_op0
//~     15        adr_op1
//~     16        f15
//~     17        fOPC_AEQ
//~     18        fOPC_RET
//~     19        fOPC_CALL
//~     20        fAP_ONE
//~     21        fAP_ADD
//~     22        fPC_JNZ
//~     23        fPC_REL
//~     24        fPC_ABS
//~     25        fRES_MUL
//~     26        fRES_ADD
//~     27        fOP1_AP
//~     28        fOP1_FP
//~     29        fOP1_VAL
//~     30        fOP0_FP
//~     31        fDST_FP
//~     32        mem0
//~     33        mem1
//~     34        mem2
//~     35        mem3
//~     36        val0
//~     37        val1
//~     38        val2
//~     39        val3

pub struct Instruction<F>(PhantomData<F>);

impl<F> Argument<F> for Instruction<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::CairoInstruction);
    const CONSTRAINTS: u32 = 41;

    /// Generates the constraints for the Cairo instruction
    ///     Accesses Curr and Next rows
    fn constraints() -> Vec<E<F>> {
        // load all variables of the witness corresponding to Cairoinstruction gates
        let pc = witness_curr(COL_PC);
        let ap = witness_curr(COL_AP);
        let fp = witness_curr(COL_FP);
        let instr = witness_curr(COL_INSTR);
        //let perm = witness_curr(COL_PERM);
        let size = witness_curr(COL_SIZE);
        let res = witness_curr(COL_RES);
        let dst = witness_curr(COL_DST);
        let op0 = witness_curr(COL_OP0);
        let op1 = witness_curr(COL_OP1);
        let off_dst = witness_curr(COL_OFF_DST);
        let off_op0 = witness_curr(COL_OFF_OP0);
        let off_op1 = witness_curr(COL_OFF_OP1);
        let adr_dst = witness_curr(COL_ADR_DST);
        let adr_op0 = witness_curr(COL_ADR_OP0);
        let adr_op1 = witness_curr(COL_ADR_OP1);

        let f15 = witness_curr(COL_F_15);
        let f_opc_aeq = witness_curr(COL_F_OPC_AEQ);
        let f_opc_ret = witness_curr(COL_F_OPC_RET);
        let f_opc_call = witness_curr(COL_F_OPC_CALL);
        let f_ap_one = witness_curr(COL_F_AP_ONE);
        let f_ap_add = witness_curr(COL_F_AP_ADD);
        let f_pc_jnz = witness_curr(COL_F_PC_JNZ);
        let f_pc_rel = witness_curr(COL_F_PC_REL);
        let f_pc_abs = witness_curr(COL_F_PC_ABS);
        let f_res_mul = witness_curr(COL_F_RES_MUL);
        let f_res_add = witness_curr(COL_F_RES_ADD);
        let f_op1_ap = witness_curr(COL_F_OP1_AP);
        let f_op1_fp = witness_curr(COL_F_OP1_FP);
        let f_op1_val = witness_curr(COL_F_OP1_VAL);
        let f_op0_fp = witness_curr(COL_F_OP0_FP);
        let f_dst_fp = witness_curr(COL_F_DST_FP);

        let mem: Vec<Expr<ConstantExpr<F>>> =
            (0..ACC_PER_INS).map(|i| witness_curr(COL_MEM[i])).collect();
        let val: Vec<Expr<ConstantExpr<F>>> =
            (0..ACC_PER_INS).map(|i| witness_curr(COL_VAL[i])).collect();

        let next_pc = witness_next(0);
        let next_ap = witness_next(1);
        let next_fp = witness_next(2);
        let next_mem = witness_next(COL_MEM[0]);
        let next_val = witness_next(COL_VAL[0]);
        //let next_perm = witness_next(COL_PERM);

        // store flags in array
        let flags: Vec<Expr<ConstantExpr<F>>> =
            (COL_F_DST_FP..=COL_F_15).map(|i| witness_curr(i)).collect();

        // LIST OF CONSTRAINTS
        // -------------------

        // INSTRUCTIONS RELATED

        // Perhaps Redundant if we perform the instruction well formness check
        // * Check last flag is always zero
        // f15 == 0
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![f15];
        let mut cache = Cache::default();

        // * Check booleanity of all flags
        // fi * (1-fi) == 0 for i=[0..15)
        for flag in flags.iter().take(NUM_FLAGS - 1) {
            constraints.push(flag.clone() * (E::one() - flag.clone()));
        }

        // * Check no two flagbits of the same flagset are nonzero
        // TODO(querolita): perhaps these are redundant considering all of the logics below
        let op1_src = cache.cache(f_op1_ap.clone() + f_op1_fp.clone() + f_op1_val.clone());
        let res_log = cache.cache(f_res_mul.clone() + f_res_add.clone());
        let pc_up = cache.cache(f_pc_jnz.clone() + f_pc_rel.clone() + f_pc_abs.clone());
        let ap_up = cache.cache(f_ap_one.clone() + f_ap_add.clone());
        let opcode = cache.cache(f_opc_aeq.clone() + f_opc_ret.clone() + f_opc_call.clone());
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
            // recompose instruction as: flags[15..0] | op1_sft | op0_sft | dst_sft
            let mut aux: Expr<ConstantExpr<F>> = flags[NUM_FLAGS - 1].clone();
            for i in (0..NUM_FLAGS - 1).rev() {
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
          - (f_op1_ap.clone() * ap.clone()                                                     // if op1_src == 4 : ap
          + f_op1_fp.clone() * fp.clone()                                                      // if op1_src == 2 : fp
          + f_op1_val.clone() * pc.clone()                                                     // if op1_src == 1 : pc
          + (E::one() - f_op1_fp - f_op1_ap - f_op1_val) * op0.clone() // if op1_src == 0 : op0
          + off_op1), //                                                                                        + off_op1
        );

        // OPERATIONS-RELATED

        // * Check value of result
        constraints.push(
            (E::one() - f_pc_jnz.clone()) * res.clone()                              // if pc_up != 4 : res = ..        // no res in conditional jumps
          - (f_res_mul.clone() * op0.clone() * op1.clone()                     //      if res_log = 2 : op0 * op1
          + f_res_add.clone() * (op0.clone() + op1.clone())                    //      if res_log = 1 : op0 + op1
          + (E::one() - f_res_add - f_res_mul) * op1.clone()), //      if res_log = 0 : op1
        );

        // * Check storage of current fp for a call instruction
        // <=> assert_eq!(dst, fp);
        constraints.push(f_opc_call.clone() * (dst.clone() - fp.clone())); // if opcode = 1 : dst = fp

        // * Check storage of next instruction after a call instruction
        // <=> assert_eq!(op0, pc + size); // checks [ap+1] contains instruction after call
        constraints.push(f_opc_call.clone() * (op0 - (pc.clone() + size.clone()))); // if opcode = 1 : op0 = pc + size

        // * Check destination = result after assert-equal
        // <=> assert_eq!(res, dst);
        constraints.push(f_opc_aeq * (dst.clone() - res.clone())); // if opcode = 4 : dst = res

        // -----------------
        // TRANSITION-RELATED
        // * Check next allocation pointer
        //  next_ap =
        //             ap +
        //  if ap_up == 1  : res
        //  if ap_up == 2  : 1
        // if opcode == 1  : 2
        constraints.push(
            next_ap
                - (ap.clone() + f_ap_add * res.clone() + f_ap_one + f_opc_call.clone().double()),
        );

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

        // -----------------
        // MEMORY-RELATED
        // Singularity and continuity of the memory
        for i in 0..ACC_PER_INS {
            let (nextmem, nextval) = {
                if i != ACC_PER_INS - 1 {
                    (mem[i + 1].clone(), val[i + 1].clone())
                } else {
                    (next_mem.clone(), next_val.clone())
                }
            };
            // Continuity
            // (a'_i+1 - a'_i)(a'_i+1 - a'_i - 1)
            constraints.push(
                (nextmem.clone() - mem[i].clone()) * (nextmem.clone() - mem[i].clone() - E::one()),
            );
            // Singularity
            // (v'_i+1 - v'_i)(a'_i+1 - a'_i - 1)
            constraints.push(
                (nextval.clone() - val[i].clone()) * (nextmem.clone() - mem[i].clone() - E::one()),
            );
        }
        // Permutation of the sorted list (mem, val) vs (pc,instr)&(dst_adr,dst)&(op0_adr,op0)&(op1_adr,op1)
        // perm_i * (z - (mem_i+1 + a val_i+1)) = perm_i+1 * (z - (mem'_i+1 + a val'_i+1))
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
        let perm_fin = witness_curr(0);
        let pc0 = witness_curr(1);
        let ap0 = witness_curr(2);
        let fp0 = witness_curr(3);
        let pc_t = witness_curr(4);
        let ap_t = witness_curr(5);
        let pc_ini = witness_curr(6);
        let ap_ini = witness_curr(7);
        let pc_fin = witness_curr(8);
        let ap_fin = witness_curr(9);

        // LIST OF CONSTRAINTS
        let mut constraints: Vec<Expr<ConstantExpr<F>>> = vec![perm_fin - E::one()];
        // * Check initial and final ap, fp, pc
        constraints.push(ap0 - ap_ini.clone()); // ap0 = ini_ap
        constraints.push(fp0 - ap_ini); // fp0 = ini_ap
        constraints.push(ap_t - ap_fin); // apT = fin_ap
        constraints.push(pc0 - pc_ini); // pc0 = ini_pc
        constraints.push(pc_t - pc_fin); // pcT = fin_pc

        constraints
    }
}
