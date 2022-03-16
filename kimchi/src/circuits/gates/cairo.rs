//! This source file implements the Cairo gate primitive

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr::{self, Column};
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::polynomials;
use crate::circuits::scalars::ProofEvaluations;
use crate::circuits::wires::{GateWires, Wire, COLUMNS};
use ark_ff::{FftField, Field};
use array_init::array_init;
use cairo::{
    runner::{CairoInstruction, CairoProgram, Pointers},
    word::{FlagBits, Offsets},
};
use rand::prelude::StdRng;
use rand::SeedableRng;

const NUM_FLAGS: usize = 16;
pub const CIRCUIT_GATE_COUNT: usize = 3;

fn gate_type_to_selector<F: FftField>(typ: GateType) -> [F; CIRCUIT_GATE_COUNT] {
    match typ {
        GateType::CairoInstruction => [F::one(), F::zero(), F::zero()],
        GateType::CairoTransition => [F::zero(), F::one(), F::zero()],
        GateType::CairoClaim => [F::zero(), F::zero(), F::one()],
        _ => [F::zero(); CIRCUIT_GATE_COUNT],
    }
}

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

/// Returns the witness of an execution of a Cairo program in CircuitGate format
pub fn cairo_witness<F: Field>(prog: &CairoProgram<F>) -> [Vec<F>; COLUMNS] {
    // 2 row per instruction for CairoInstruction gate
    // 1 row per instruction for CairoTransition gate
    // final row for CairoClaim gate
    let n = prog.trace().len();
    let rows = 3 * n + 1;
    let mut table: Vec<[F; COLUMNS]> = Vec::new();
    table.resize(rows, [F::zero(); COLUMNS]);
    for (i, inst) in prog.trace().iter().enumerate() {
        let gate = instruction_witness(inst);
        let state = gate[0];
        let flags = gate[1];
        table[2 * i] = state;
        table[2 * i + 1] = flags;
        table[2 * n + i] = transition_witness(inst);
    }
    table[rows - 1] = claim_witness(prog);

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

fn claim_witness<F: Field>(prog: &CairoProgram<F>) -> [F; COLUMNS] {
    let first = 0;
    let last = prog.trace().len() - 1;
    [
        prog.trace()[first].pc(),
        prog.trace()[first].ap(),
        prog.trace()[first].fp(),
        prog.trace()[last].pc(),
        prog.trace()[last].ap(),
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

fn transition_witness<F: Field>(inst: &CairoInstruction<F>) -> [F; COLUMNS] {
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

fn instruction_witness<F: Field>(inst: &CairoInstruction<F>) -> [[F; COLUMNS]; 2] {
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
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let curr: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let mut next: [F; COLUMNS] = array_init(|_| F::zero());
        if self.typ != GateType::CairoClaim {
            next = array_init(|i| witness[i][row + 1]);
        }

        // column polynomials
        let polys = {
            let mut h = std::collections::HashSet::new();
            for i in 0..COLUMNS {
                h.insert(Column::Witness(i)); // column witness polynomials
            }
            // gate selector polynomials
            h.insert(Column::Index(GateType::CairoInstruction));
            h.insert(Column::Index(GateType::CairoTransition));
            h.insert(Column::Index(GateType::CairoClaim));
            h.insert(Column::Index(GateType::Zero));
            h
        };

        // assign powers of alpha to these gates
        let mut alphas = Alphas::<F>::default();
        alphas.register(
            ArgumentType::Gate(self.typ),
            polynomials::cairo::Instruction::<F>::CONSTRAINTS,
        );

        // Get constraints for this circuit gate
        let constraints = polynomials::cairo::circuit_gate_combined_constraints(self.typ, &alphas);

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
            GateType::Zero => Ok(()),
            GateType::CairoInstruction => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_instruction(&this, &next)
            }
            GateType::CairoTransition => {
                let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);
                CircuitGate::ensure_transition(&this, &next)
            }
            GateType::CairoClaim => CircuitGate::ensure_claim(&this),
            // TODO(querolita): memory related checks
            _ => Err(
                "Incorrect GateType: expected CairoInstruction, CairoTransition, or CairoClaim"
                    .to_string(),
            ),
        }
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
        let f_pc_abs = flags[0];
        let f_pc_rel = flags[1];
        let f_pc_jnz = flags[2];
        let f_ap_inc = flags[3];
        let f_ap_one = flags[4];
        let f_opc_call = flags[5];
        let f_opc_ret = flags[6];
        let f_opc_aeq = flags[7];
        let f_dst_fp = flags[8];
        let f_op0_fp = flags[9];
        let f_op1_val = flags[10];
        let f_op1_fp = flags[11];
        let f_op1_ap = flags[12];
        let f_res_add = flags[13];
        let f_res_mul = flags[14];

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
        // rotate flags to its natural ordering
        let mut flags: Vec<F> = (0..NUM_FLAGS - 1).map(|i| flags[i]).collect();
        flags.rotate_right(7);

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

    fn ensure_transition(curr: &[F], next: &[F]) -> Result<(), String> {
        let pc = curr[0];
        let ap = curr[1];
        let fp = curr[2];
        let size = curr[3];
        let res = curr[4];
        let dst = curr[5];
        let op1 = curr[6];
        let f_pc_abs = curr[7];
        let f_pc_rel = curr[8];
        let f_pc_jnz = curr[9];
        let f_ap_inc = curr[10];
        let f_ap_one = curr[11];
        let f_opc_call = curr[12];
        let f_opc_ret = curr[13];
        let next_pc = next[0];
        let next_ap = next[1];
        let next_fp = next[2];

        let zero = F::zero();
        let one = F::one();
        let two = F::from(2u16);

        // REGISTERS RELATED

        // * Check next allocation pointer
        ensure_eq!(
            next_ap, //               next_ap =
            ap                   //             ap +
            + f_ap_inc * res      //  if ap_up == 1 : res
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineCurve;
    use cairo::{helper::*, memory::CairoMemory};
    use mina_curves::pasta::fp::Fp as F;
    use mina_curves::pasta::pallas;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;

    // creates a constraint system for a number of Cairo instructions
    fn create_test_consys(inirow: usize, ninstr: usize) -> ConstraintSystem<PallasField> {
        let gates = CircuitGate::<PallasField>::create_cairo_gadget(inirow, ninstr);
        ConstraintSystem::create(gates, vec![], oracle::pasta::fp_kimchi::params(), 0).unwrap()
    }

    #[test]
    fn test_cairo_cs() {
        let instrs: Vec<i128> = vec![
            0x400380007ffc7ffd,
            0x482680017ffc8000,
            1,
            0x208b7fff7fff7ffe,
            0x480680017fff8000,
            10,
            0x48307fff7fff8000,
            0x48507fff7fff8000,
            0x48307ffd7fff8000,
            0x480a7ffd7fff8000,
            0x48127ffb7fff8000,
            0x1104800180018000,
            -11,
            0x48127ff87fff8000,
            0x1104800180018000,
            -14,
            0x48127ff67fff8000,
            0x1104800180018000,
            -17,
            0x208b7fff7fff7ffe,
            /*41, // beginning of outputs
            44,   // end of outputs
            44,   // input
            */
        ];

        let mut mem = CairoMemory::<F>::new(F::vec_to_field(&instrs));
        // Need to know how to find out
        mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
        mem.write(F::from(22u32), F::from(44u32)); // end of outputs
        mem.write(F::from(23u32), F::from(44u32)); //end of program
        let prog = CairoProgram::new(&mut mem, 5, 24);

        let witness = cairo_witness(&prog);

        // Create the Cairo circuit
        let ninstr = prog.trace().len();
        let inirow = 0;
        let circuit = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

        let cs = create_test_consys(inirow, ninstr);

        // Verify each gate
        let mut row = 0;
        for gate in circuit {
            let res = gate.verify_cairo_gate(row, &witness, &cs);
            if res.is_err() {
                println!("{:?}", res);
            }
            row = row + 1;
        }
    }

    #[test]
    fn test_long_cairo_gate() {
        let instrs: Vec<i128> = vec![
            0x400380007ffc7ffd,
            0x482680017ffc8000,
            1,
            0x208b7fff7fff7ffe,
            0x480680017fff8000,
            10,
            0x48307fff7fff8000,
            0x48507fff7fff8000,
            0x48307ffd7fff8000,
            0x480a7ffd7fff8000,
            0x48127ffb7fff8000,
            0x1104800180018000,
            -11,
            0x48127ff87fff8000,
            0x1104800180018000,
            -14,
            0x48127ff67fff8000,
            0x1104800180018000,
            -17,
            0x208b7fff7fff7ffe,
            /*41, // beginning of outputs
            44,   // end of outputs
            44,   // input
            */
        ];

        let mut mem = CairoMemory::<F>::new(F::vec_to_field(&instrs));
        // Need to know how to find out
        mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
        mem.write(F::from(22u32), F::from(44u32)); // end of outputs
        mem.write(F::from(23u32), F::from(44u32)); //end of program
        let prog = CairoProgram::new(&mut mem, 5, 24);

        let witness = cairo_witness(&prog);
        //view_witness(&witness);

        // Create the Cairo circuit
        let num = prog.trace().len();
        let circuit = CircuitGate::<F>::create_cairo_gadget(0, num);

        // Verify each gate
        let mut row = 0;
        for gate in circuit {
            let res = gate.ensure_cairo_gate(row, &witness);
            if res.is_err() {
                println!("{:?}", res);
            }
            row = row + 1;
        }
    }

    #[test]
    fn test_cairo_gate() {
        // Compute the Cairo witness
        let instrs = vec![
            F::from(0x480680017fff8000u64),
            F::from(10u64),
            F::from(0x208b7fff7fff7ffeu64),
        ];
        let mut mem = CairoMemory::<F>::new(instrs);
        mem.write(F::from(4u32), F::from(7u32)); //beginning of output
        mem.write(F::from(5u32), F::from(7u32)); //end of output
        let prog = CairoProgram::new(&mut mem, 1, 6);
        let witness = cairo_witness(&prog);
        //view_witness(&witness);

        // Create the Cairo circuit
        let num = prog.trace().len();
        let circuit = CircuitGate::<F>::create_cairo_gadget(0, num);

        // Verify each gate
        let mut row = 0;
        for gate in circuit {
            let res = gate.ensure_cairo_gate(row, &witness);
            if res.is_err() {
                println!("{:?}", res);
            }
            row = row + 1;
        }
    }
}
