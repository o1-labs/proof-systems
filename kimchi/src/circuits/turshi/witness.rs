//! This module contains the linking interface between the computation of the witness and
//! the generation of a Kimchi-compatible execution trace

use crate::circuits::polynomial::COLUMNS;
use crate::circuits::turshi::cairo::runner::{CairoInstruction, CairoProgram, Pointers};
use ark_ff::Field;

use super::cairo::word::{FlagBits, Offsets};

/*
pub fn view_witness<F: Field>(witness: &[Vec<F>; COLUMNS]) {
    let rows = witness[0].len();
    for i in 0..rows {
        print!("row {}: [", i);
        for j in 0..witness.len() {
            print!("{} , ", witness[j][i].to_u64());
        }
        println!("]");
    }
}

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

/// Returns
pub fn cairo_witness<F: Field>(prog: &CairoProgram<F>) -> [Vec<F>; COLUMNS] {
    // 2 row per instruction for CairoInstruction gate
    // 1 row per instruction for CairoTransition gate
    // final row for CairoClaim gate
    let n = prog.trace().len();
    let rows = 3 * n + 1;
    let mut table: Vec<[F; COLUMNS]> = Vec::new();
    table.resize(rows, [F::zero(); COLUMNS]);
    for (i, inst) in prog.trace().iter().enumerate() {
        let gate = instruction_gate(inst);
        let state = gate[0];
        let flags = gate[1];
        table[2 * i] = state;
        table[2 * i + 1] = flags;
        table[2 * n + i] = transition_gate(inst);
    }
    table[rows - 1] = claim_gate(prog);

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

fn claim_gate<F: Field>(prog: &CairoProgram<F>) -> [F; COLUMNS] {
    let first = 0;
    let last = prog.trace().len() - 1;
    [
        prog.trace()[first].pc(),
        prog.trace()[first].ap(),
        prog.trace()[first].fp(),
        prog.trace()[last].pc(),
        prog.trace()[last].ap(), // perhaps this is the pre-last
        prog.ini().pc(),
        prog.ini().ap(),
        prog.fin().pc(),
        prog.fin().ap(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
        F::zero(),
    ]
}

fn transition_gate<F: Field>(inst: &CairoInstruction<F>) -> [F; COLUMNS] {
    [
        inst.pc(),
        inst.ap(),
        inst.fp(),
        inst.size(),
        inst.res(),
        inst.dst(),
        inst.op1(),
        inst.f_pc_abs(),
        inst.f_pc_rel(),
        inst.f_pc_jnz(),
        inst.f_ap_add(),
        inst.f_ap_one(),
        inst.f_opc_call(),
        inst.f_opc_ret(),
        F::zero(),
    ]
}

fn instruction_gate<F: Field>(inst: &CairoInstruction<F>) -> [[F; COLUMNS]; 2] {
    [
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
        ],
        [
            inst.f_pc_abs(),
            inst.f_pc_rel(),
            inst.f_pc_jnz(),
            inst.f_ap_add(),
            inst.f_ap_one(),
            inst.f_opc_call(),
            inst.f_opc_ret(),
            inst.f_opc_aeq(),
            inst.f_dst_fp(),
            inst.f_op0_fp(),
            inst.f_op1_val(),
            inst.f_op1_fp(),
            inst.f_op1_ap(),
            inst.f_res_add(),
            inst.f_res_mul(),
        ],
    ]
}
