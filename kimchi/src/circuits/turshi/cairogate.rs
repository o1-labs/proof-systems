//! This source file implements the Cairo gate primitive

use ark_ff::FftField;
//PrimeField, Zero
//use ark_serialize::CanonicalSerialize;
use array_init::array_init;

use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::wires::{GateWires, COLUMNS};
//use cairo::definitions::NUM_FLAGS;

const NUM_FLAGS: usize = 16;

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
                typ: GateType::CairoInstruction,
                wires: wires[1],
                coeffs: vec![],
            },
        ]
    }

    /// This function creates a 2-row CairoTransition gate
    pub fn create_cairo_transition(wires: &[GateWires; 2]) -> Vec<Self> {
        vec![
            CircuitGate {
                typ: GateType::CairoTransition,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::CairoTransition,
                wires: wires[1],
                coeffs: vec![],
            },
        ]
    }

    /// This function creates a single row CairoClaim gate
    pub fn create_cairo_claim(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::CairoClaim,
            wires,
            coeffs: vec![],
        }
    }

    // TODO(querolita): gadget generator of the whole table of rows from the runner results

    /// verifies that the Cairo gate constraints are solved by the witness depending on its type
    pub fn verify_cairo_gate(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        _cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // assignments
        let this: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);

        match self.typ {
            GateType::CairoInstruction => {
                CircuitGate::verify_instruction(&this.to_vec(), &next.to_vec())
            }
            GateType::CairoTransition => {
                CircuitGate::verify_transition(&this.to_vec(), &next.to_vec())
            }
            GateType::CairoClaim => CircuitGate::verify_claim(&this.to_vec()),
            // TODO(querolita): memory related checks
            _ => Err(
                "Incorrect GateType: expected CairoInstruction, CairoTransition, or CairoClaim"
                    .to_string(),
            ),
        }
    }

    fn verify_instruction(vars: &Vec<F>, flags: &Vec<F>) -> Result<(), String> {
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
        for i in 0..15 {
            ensure_eq!(zero, flags[i] * (one - flags[i]), "non-boolean flags");
        }

        // well formness of instruction
        // rotate flags to its natural ordering
        let idxs: Vec<usize> = (0..NUM_FLAGS - 1).collect();
        let mut flags: Vec<F> = idxs.into_iter().map(|i| flags[i]).collect();
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
            ((aux + op1_sft) * pow16 + op0_sft) * pow16 + dst_sft
        };
        ensure_eq!(
            zero,
            instr - shape,
            "wrong decomposition of the instructoin"
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

    fn verify_transition(curr: &Vec<F>, next: &Vec<F>) -> Result<(), String> {
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

    fn verify_claim(claim: &Vec<F>) -> Result<(), String> {
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
