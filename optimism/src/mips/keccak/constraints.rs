//! Keccak gadget
use ark_ff::{Field, PrimeField};
use kimchi::{
    auto_clone, auto_clone_array,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        expr::{self, constraints::ExprOps, Cache, ConstantExpr, Expr},
        gate::GateType,
    },
};
use std::marker::PhantomData;

use crate::mips::{
    column::Column,
    interpreter::{Instruction, InterpreterEnv},
};

use super::KTypeInstruction;

pub fn interpret_ktype<Env: InterpreterEnv>(env: &mut Env, instr: KTypeInstruction) {
    match instr {
        KTypeInstruction::SpongeSqueeze => (),
        KTypeInstruction::SpongeAbsorb => (),
        KTypeInstruction::SpongeAbsorbRoot => (),
        KTypeInstruction::SpongeAbsorbPad(pad_bytes) => (),
        KTypeInstruction::SpongeAbsorbRootPad(pad_bytes) => (),
        KTypeInstruction::Round(i) => (),
    }
}

/*

//~
//~ | `KeccakRound` | [0...265) | [265...1165) | [1165...1965) |
//~ | ------------- | --------- | ------------ | ------------- |
//~ | Curr          | theta     | pirho        | chi           |
//~
//~ | `KeccakRound` | [0...100) |
//~ | ------------- | --------- |
//~ | Next          | iota      |
//~
//~ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
//~
//~ | Columns  | [0...100) | [100...180) | [180...200) | [200...205) | [205...225)  | [225...245)  | [245...265)  |
//~ | -------- | --------- | ----------- | ----------- | ----------- | ------------ | ------------ | ------------ |
//~ | theta    | state_a   | shifts_c    | dense_c     | quotient_c  | remainder_c  | dense_rot_c  | expand_rot_c |
//~
//~ | Columns  | [265...665) | [665...765) | [765...865)  | [865...965) | [965...1065) | [1065...1165) |
//~ | -------- | ----------- | ----------- | ------------ | ----------- | ------------ | ------------- |
//~ | pirho    | shifts_e    | dense_e     | quotient_e   | remainder_e | dense_rot_e  | expand_rot_e  |
//~
//~ | Columns  | [1165...1565) | [1565...1965) |
//~ | -------- | ------------- | ------------- |
//~ | chi      | shifts_b      | shifts_sum    |
//~
//~ | Columns  | [0...4) | [4...100) |
//~ | -------- | ------- | --------- |
//~ | iota     | g00     | rest_g    |
//~
//~ -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
//~
//~ | `KeccakSponge` | [0...100) | [100...168) | [168...200) | [200...400] | [400...800) |
//~ | -------------- | --------- | ----------- | ----------- | ----------- | ----------- |
//~ | Curr           | old_state | new_block   | zeros       | bytes       | shifts      |
//~ | Next           | xor_state |
//~
pub fn constraints_keccak<F: Field + PrimeField>() -> Expr<ConstantExpr<F>, Column> {
    let mut constraints: Vec<_> = Vec::new();

    {
        for ktype in KeccakInstruction::iter() {
            let cell = Column::InstructionSelector(Instruction::Keccak(ktype));
            constraints.push(boolean(curr_cell(cell)));
        }
    };

    // Cache some sums

    // Check that at most 1 selector is on at any time
    constraints.push(boolean(
        r_type_selectors_sum.clone() + non_rtype_selectors_sum.clone(),
    ));

    // Check that all of the instructions are off on the final row
    constraints.push(
        E::UnnormalizedLagrangeBasis(-1) * (r_type_selectors_sum.clone() + non_rtype_selectors_sum),
    );

    // Check the correctness of r-type instruction decoding
    // **TODO**: Allow this to fail, propagate the exception
    {
        // NB: Plus one so that opcode 0 has a distinguishable effect
        let expected_opcode_plus_one = RTypeInstruction::iter()
            .map(|selector| {
                let (_, funct) = encode_rtype(selector);
                let funct = E::from((funct + 1) as u64);
                funct
                    * curr_cell(Column::InstructionSelector(InstructionSelector::RType(
                        selector,
                    )))
            })
            .reduce(|x, y| x + y)
            .unwrap();

        constraints.push(
            E::VanishesOnLastRow
                * r_type_selectors_sum
                * (expected_opcode_plus_one
                    - curr_cell(Column::InstructionPart(InstructionPart::Funct))
                    - E::one()),
        )
    }

    // Unconditional lookups
    {
        let mut env: GlobalLookupEnv<F> = GlobalLookupEnv {
            lookups: vec![],
            memory_offset: memory_offsets,
        };
        // Memory
        for i in 0..env.memory_offset.len() {
            witness::memory_lookups(&mut env, i);
        }
        // Registers
        witness::registers_lookups(&mut env);
        // Range check
        witness::range_check_16_lookups(&mut env);
        constraints.push(combine_lookups(Column::LookupTerm(0), env.lookups));
    }

    // Construct the lookup aggregation
    constraints.push(lookup_aggregation());

    let mut env = InstructionEnv {
        halted_set: false,
        constraints: vec![],
        scratch_state_idx: 0,
        lookup_terms_idx: 0,
        lookup_terms: array::from_fn(|_| vec![]),
    };

    // Decode the instruction
    {
        let _ = instructions::decode_instruction(&mut env);
        constraints.extend(env.constraints);
    }

    // Instruction constraints
    {
        let mut instruction_constraints = vec![];
        for (i, instr) in InstructionSelector::iter().enumerate() {
            if instr != InstructionSelector::IType(ITypeInstruction::BranchNeq) {
                // i % (1 << 6) != 0b110000 {
                continue;
            }
            let mut env = InstructionEnv {
                halted_set: env.halted_set,
                constraints: vec![],
                scratch_state_idx: env.scratch_state_idx,
                lookup_terms_idx: env.lookup_terms_idx,
                lookup_terms: array::from_fn(|_| vec![]),
            };
            //println!("instr: {:?}", instr);
            instructions::run_instruction(instr, &mut env);
            for j in 0..NUM_INSTRUCTION_LOOKUP_TERMS {
                //continue;
                /*if j % (1 << 0) != 0b1000 {
                    continue;
                }*/
                // TODO: Make waaaay less manual
                env.constraints.push(combine_lookups(
                    Column::LookupTerm(NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + j),
                    env.lookup_terms[NUM_DECODING_LOOKUP_TERMS + j].clone(),
                ));
            }
            if !env.constraints.is_empty() {
                instruction_constraints.push(
                    curr_cell(Column::InstructionSelector(instr))
                        * combine(env.constraints.into_iter()),
                );
            }
        }

        constraints.push({
            let x = instruction_constraints
                .into_iter()
                .reduce(|x, y| x + y)
                .unwrap_or(E::zero());
            //println!("{:#?}", x);
            x
        })
    }

    combine(constraints.into_iter())
}

#[derive(Default)]
pub struct KeccakRound<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakRound<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakRound);
    const CONSTRAINTS: u32 = 389;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>, const COLUMNS: usize>(
        env: &ArgumentEnv<F, T, COLUMNS>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let mut constraints = vec![];

        // DEFINE ROUND CONSTANT
        let rc = [env.coeff(0), env.coeff(1), env.coeff(2), env.coeff(3)];

        // LOAD STATES FROM WITNESS LAYOUT
        // THETA
        let state_a = grid!(100, env.witness_curr_chunk(0, 100));
        let shifts_c = grid!(80, env.witness_curr_chunk(100, 180));
        let dense_c = grid!(20, env.witness_curr_chunk(180, 200));
        let quotient_c = grid!(5, env.witness_curr_chunk(200, 205));
        let remainder_c = grid!(20, env.witness_curr_chunk(205, 225));
        let dense_rot_c = grid!(20, env.witness_curr_chunk(225, 245));
        let expand_rot_c = grid!(20, env.witness_curr_chunk(245, 265));
        // PI-RHO
        let shifts_e = grid!(400, env.witness_curr_chunk(265, 665));
        let dense_e = grid!(100, env.witness_curr_chunk(665, 765));
        let quotient_e = grid!(100, env.witness_curr_chunk(765, 865));
        let remainder_e = grid!(100, env.witness_curr_chunk(865, 965));
        let dense_rot_e = grid!(100, env.witness_curr_chunk(965, 1065));
        let expand_rot_e = grid!(100, env.witness_curr_chunk(1065, 1165));
        // CHI
        let shifts_b = grid!(400, env.witness_curr_chunk(1165, 1565));
        let shifts_sum = grid!(400, env.witness_curr_chunk(1565, 1965));
        // IOTA
        let state_g = grid!(100, env.witness_next_chunk(0, 100));

        // Define vectors containing witness expressions which are not in the layout for efficiency
        let mut state_c: Vec<Vec<T>> = vec![vec![T::zero(); QUARTERS]; DIM];
        let mut state_d: Vec<Vec<T>> = vec![vec![T::zero(); QUARTERS]; DIM];
        let mut state_e: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];
        let mut state_b: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];
        let mut state_f: Vec<Vec<Vec<T>>> = vec![vec![vec![T::zero(); QUARTERS]; DIM]; DIM];

        // STEP theta: 5 * ( 3 + 4 * 1 ) = 35 constraints
        for x in 0..DIM {
            let word_c = from_quarters!(dense_c, x);
            let rem_c = from_quarters!(remainder_c, x);
            let rot_c = from_quarters!(dense_rot_c, x);

            constraints
                .push(word_c * T::two_pow(1) - (quotient_c(x) * T::two_pow(64) + rem_c.clone()));
            constraints.push(rot_c - (quotient_c(x) + rem_c));
            constraints.push(boolean(&quotient_c(x)));

            for q in 0..QUARTERS {
                state_c[x][q] = state_a(0, x, q)
                    + state_a(1, x, q)
                    + state_a(2, x, q)
                    + state_a(3, x, q)
                    + state_a(4, x, q);
                constraints.push(state_c[x][q].clone() - from_shifts!(shifts_c, x, q));

                state_d[x][q] =
                    shifts_c(0, (x + DIM - 1) % DIM, q) + expand_rot_c((x + 1) % DIM, q);

                for y in 0..DIM {
                    state_e[y][x][q] = state_a(y, x, q) + state_d[x][q].clone();
                }
            }
        } // END theta

        // STEP pirho: 5 * 5 * (2 + 4 * 1) = 150 constraints
        for (y, col) in OFF.iter().enumerate() {
            for (x, off) in col.iter().enumerate() {
                let word_e = from_quarters!(dense_e, y, x);
                let quo_e = from_quarters!(quotient_e, y, x);
                let rem_e = from_quarters!(remainder_e, y, x);
                let rot_e = from_quarters!(dense_rot_e, y, x);

                constraints.push(
                    word_e * T::two_pow(*off) - (quo_e.clone() * T::two_pow(64) + rem_e.clone()),
                );
                constraints.push(rot_e - (quo_e.clone() + rem_e));

                for q in 0..QUARTERS {
                    constraints.push(state_e[y][x][q].clone() - from_shifts!(shifts_e, y, x, q));
                    state_b[(2 * x + 3 * y) % DIM][y][q] = expand_rot_e(y, x, q);
                }
            }
        } // END pirho

        // STEP chi: 4 * 5 * 5 * 2 = 200 constraints
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    let not = T::literal(F::from(0x1111111111111111u64))
                        - shifts_b(0, y, (x + 1) % DIM, q);
                    let sum = not + shifts_b(0, y, (x + 2) % DIM, q);
                    let and = shifts_sum(1, y, x, q);

                    constraints.push(state_b[y][x][q].clone() - from_shifts!(shifts_b, y, x, q));
                    constraints.push(sum - from_shifts!(shifts_sum, y, x, q));
                    state_f[y][x][q] = shifts_b(0, y, x, q) + and;
                }
            }
        } // END chi

        // STEP iota: 4 constraints
        for (q, c) in rc.iter().enumerate() {
            constraints.push(state_g(0, 0, q) - (state_f[0][0][q].clone() + c.clone()));
        } // END iota

        constraints
    }
}

//~
//~ | `KeccakSponge` | [0...100) | [100...168) | [168...200) | [200...400] | [400...800) |
//~ | -------------- | --------- | ----------- | ----------- | ----------- | ----------- |
//~ | Curr           | old_state | new_block   | zeros       | bytes       | shifts      |
//~ | Next           | xor_state |
//~
#[derive(Default)]
pub struct KeccakSponge<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakSponge<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakSponge);
    const CONSTRAINTS: u32 = 568;

    // Constraints for one round of the Keccak permutation function
    fn constraint_checks<T: ExprOps<F>, const COLUMNS: usize>(
        env: &ArgumentEnv<F, T, COLUMNS>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        let mut constraints = vec![];

        // LOAD WITNESS
        let old_state = env.witness_curr_chunk(0, 100);
        let new_block = env.witness_curr_chunk(100, 200);
        let zeros = env.witness_curr_chunk(168, 200);
        let xor_state = env.witness_next_chunk(0, 100);
        let bytes = env.witness_curr_chunk(200, 400);
        let shifts = env.witness_curr_chunk(400, 800);
        auto_clone_array!(old_state);
        auto_clone_array!(new_block);
        auto_clone_array!(xor_state);
        auto_clone_array!(bytes);
        auto_clone_array!(shifts);

        // LOAD COEFFICIENTS
        let absorb = env.coeff(0);
        let squeeze = env.coeff(1);
        let root = env.coeff(2);
        let flags = env.coeff_chunk(4, 140);
        let pad = env.coeff_chunk(200, 336);
        auto_clone!(root);
        auto_clone!(absorb);
        auto_clone!(squeeze);
        auto_clone_array!(flags);
        auto_clone_array!(pad);

        // 32 + 100 * 4 + 136 = 568
        for z in zeros {
            // Absorb phase pads with zeros the new state
            constraints.push(absorb() * z);
        }
        for i in 0..QUARTERS * DIM * DIM {
            // In first absorb, root state is all zeros
            constraints.push(root() * old_state(i));
            // Absorbs the new block by performing XOR with the old state
            constraints.push(absorb() * (xor_state(i) - (old_state(i) + new_block(i))));
            // In absorb, Check shifts correspond to the decomposition of the new state
            constraints.push(absorb() * (new_block(i) - from_shifts!(shifts, i)));
            // In squeeze, Check shifts correspond to the 256-bit prefix digest of the old state (current)
            constraints.push(squeeze() * (old_state(i) - from_shifts!(shifts, i)));
        }
        for i in 0..136 {
            // Check padding
            constraints.push(flags(i) * (pad(i) - bytes(i)));
        }

        constraints
    }
}
*/
