use crate::mips::{
    NUM_DECODING_LOOKUP_TERMS, NUM_GLOBAL_LOOKUP_TERMS, NUM_INSTRUCTION_LOOKUP_TERMS,
    NUM_LOOKUP_TERMS,
};
use kimchi::circuits::{
    expr::{self, ConstantExpr, Expr},
    gate::CurrOrNext,
};

use crate::lookup::{GlobalLookupEnvironment, Lookup};

use crate::mips::interpreter;

use crate::mips::{
    columns::{Column, FixedColumn, LookupCounter},
    interpreter::{InstructionEnvironment,
                  ITypeInstruction, Instruction,
                  InstructionPart, JTypeInstruction, RTypeInstruction
    },
    interpreter::{encode_rtype, encode_selector},
    witness,
};
use ark_ff::{Field, One, PrimeField, Zero};
use std::array;
use strum::IntoEnumIterator;

type E<F> = Expr<ConstantExpr<F>, Column>;

pub fn boolean<F: Field>(x: E<F>) -> E<F> {
    x.clone() * (x - Expr::one())
}

pub fn combine<F: Field>(constraints: impl Iterator<Item = E<F>>) -> E<F> {
    //let mask = 0b0001010;
    //let filter = 0b0000010;
    constraints
        /*.enumerate()
        .filter_map(|(i, x)| {
            if i & mask == filter {
                println!("constraint\n{:?}", x);
                Some(x)
            } else {
                None
            }
        })*/
        .reduce(|acc, x| Expr::constant(ConstantExpr::Alpha) * acc + x)
        .unwrap_or(E::zero())
}

pub fn curr_cell<F: Field>(col: Column) -> E<F> {
    Expr::cell(col, CurrOrNext::Curr)
}

pub fn next_cell<F: Field>(col: Column) -> E<F> {
    Expr::cell(col, CurrOrNext::Next)
}

pub fn lookup_aggregation<F: Field>() -> E<F> {
    let lookup_aggregation_change =
        next_cell(Column::LookupAggregation) - curr_cell(Column::LookupAggregation);
    (0..NUM_LOOKUP_TERMS).fold(lookup_aggregation_change, |acc, i| {
        acc - curr_cell(Column::LookupTerm(i))
    })
}

pub fn combine_lookups<F: Field>(column: Column, lookups: Vec<Lookup<E<F>>>) -> E<F> {
    let denominators = lookups
        .iter()
        .map(|x| {
            let combined_value = x.value.iter().rev().fold(E::zero(), |x, y| {
                x * E::Constant(ConstantExpr::JointCombiner) + y.clone()
            }) * E::Constant(ConstantExpr::JointCombiner)
                + x.table_id.clone();
            E::Constant(ConstantExpr::Beta) + combined_value
        })
        .collect::<Vec<_>>();
    let lhs = denominators
        .iter()
        .fold(curr_cell(column), |acc, x| acc * x.clone());
    let rhs = lookups
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            denominators
                .iter()
                .enumerate()
                .fold(
                    x.numerator,
                    |acc, (j, y)| {
                        if i == j {
                            acc
                        } else {
                            acc * y.clone()
                        }
                    },
                )
        })
        .reduce(|x, y| x + y)
        .unwrap_or(E::zero());
    lhs - rhs
}

struct GlobalLookupEnv<Fp> {
    lookups: Vec<Lookup<E<Fp>>>,
    memory_offset: Vec<u32>,
}

impl<Fp: Field> GlobalLookupEnvironment for GlobalLookupEnv<Fp> {
    type Fp = E<Fp>;

    fn initial_memory(&self, idx: usize) -> Self::Fp {
        curr_cell(Column::InitialMemory(idx))
    }
    fn final_memory(&self, idx: usize) -> Self::Fp {
        curr_cell(Column::FinalMemory(idx))
    }
    fn final_memory_write_index(&self, idx: usize) -> Self::Fp {
        curr_cell(Column::FinalMemoryWriteIndex(idx))
    }
    fn memory_offset(&self, idx: usize) -> Self::Fp {
        E::from(self.memory_offset[idx] as u64)
    }

    fn initial_registers(&self) -> Self::Fp {
        curr_cell(Column::InitialRegisters)
    }
    fn final_registers(&self) -> Self::Fp {
        curr_cell(Column::FinalRegisters)
    }
    fn final_registers_write_index(&self) -> Self::Fp {
        curr_cell(Column::FinalRegistersWriteIndex)
    }

    fn lookup_counters(&self, col: LookupCounter) -> Self::Fp {
        curr_cell(Column::LookupCounter(col))
    }

    fn row_number(&self) -> Self::Fp {
        curr_cell(Column::FixedColumn(FixedColumn::Counter))
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>) {
        self.lookups.push(lookup)
    }
}

struct InstructionEnv<Fp> {
    halted_set: bool,
    constraints: Vec<E<Fp>>,
    scratch_state_idx: usize,
    lookup_terms_idx: usize,
    lookup_terms: [Vec<Lookup<E<Fp>>>; NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS],
}

impl<Fp: Field> InstructionEnvironment for InstructionEnv<Fp> {
    type Column = Column;
    type Variable = E<Fp>;
    type Fp = E<Fp>;

    fn current_row(&self) -> Self::Variable {
        curr_cell(Column::FixedColumn(FixedColumn::Counter))
    }

    fn constant(x: u32) -> Self::Variable {
        E::constant((x as u64).into())
    }

    fn to_fp(x: Self::Variable) -> Self::Fp {
        x
    }

    fn instruction_pointer(&self) -> Self::Variable {
        curr_cell(Column::InstructionPointer)
    }

    fn set_instruction_pointer(&mut self, ip: &Self::Variable) {
        //println!("ip: {:?}", ip);
        self.constraints
            .push(next_cell(Column::InstructionPointer) - ip.clone())
    }

    fn halted(&self) -> Self::Variable {
        if self.halted_set {
            next_cell(Column::Halt)
        } else {
            curr_cell(Column::Halt)
        }
    }

    fn set_halted(&mut self, value: &Self::Variable) {
        self.halted_set = true;
        self.constraints.push(self.halted() - value.clone());
    }

    fn memory_accessible(
        &mut self,
        _is_enabled: &Self::Variable,
        column: Self::Column,
        _addresses: Vec<&Self::Variable>,
    ) -> Self::Variable {
        // TODO: Validate
        curr_cell(column)
    }

    fn read_memory(
        &mut self,
        output: Self::Column,
        _address: &Self::Variable,
        _accessible: &Self::Variable,
    ) -> Self::Variable {
        curr_cell(output)
    }

    fn get_register_value(
        &mut self,
        _register_idx: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable {
        curr_cell(output_value)
    }

    fn set_register_value(&mut self, _register_idx: &Self::Variable, _value: &Self::Variable) {}

    fn last_register_write(
        &mut self,
        _register_idx: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        curr_cell(output_last_write)
    }

    fn set_last_register_write(
        &mut self,
        _register_idx: &Self::Variable,
        _last_write: &Self::Variable,
    ) {
    }

    fn get_memory_value(
        &mut self,
        _address: &Self::Variable,
        _enabled_if: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable {
        curr_cell(output_value)
    }

    fn set_memory_value(
        &mut self,
        _address: &Self::Variable,
        _enabled_if: &Self::Variable,
        _value: &Self::Variable,
    ) {
    }

    fn last_memory_write(
        &mut self,
        _address: &Self::Variable,
        _enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        curr_cell(output_last_write)
    }

    fn set_last_memory_write(
        &mut self,
        _address: &Self::Variable,
        _enabled_if: &Self::Variable,
        _last_write: &Self::Variable,
    ) {
    }

    fn instruction_part(&self, part: InstructionPart) -> Self::Variable {
        curr_cell(Column::InstructionPart(part))
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>) {
        let curr_count = self.lookup_terms[self.lookup_terms_idx].len();
        if self.lookup_terms_idx < NUM_DECODING_LOOKUP_TERMS {
            if curr_count >= 7 {
                self.lookup_terms_idx += 1
            }
        } else {
            if curr_count >= 6 {
                self.lookup_terms_idx += 1
            }
        }
        self.lookup_terms[self.lookup_terms_idx].push(lookup)
    }

    fn increment_range_check_counter(&mut self, _value: &Self::Variable) {}

    fn range_check_1(&mut self, value: &Self::Variable) {
        self.constraints
            .push((value.clone() - E::one()) * value.clone());
    }

    fn range_check_2(&mut self, value: &Self::Variable) {
        self.constraints.push(
            (value.clone() - E::from(3u64))
                * (value.clone() - E::from(2u64))
                * (value.clone() - E::one())
                * value.clone(),
        );
    }

    fn decompose(
        &mut self,
        _value: &Self::Variable,
        decomposition_little_endian: Vec<u32>,
        outputs: Vec<Self::Column>,
    ) -> Vec<Self::Variable> {
        // TODO
        decomposition_little_endian
            .into_iter()
            .zip(outputs.into_iter())
            .map(|(_, column)| curr_cell(column))
            .collect()
    }

    fn div_rem(
        &mut self,
        numerator: &Self::Variable,
        denominator: &Self::Variable,
        output_div: Self::Column,
        output_rem: Self::Column,
        output_divide_by_zero: Self::Column,
    ) -> (Self::Variable, Self::Variable, Self::Variable) {
        let div = curr_cell(output_div);
        let rem = curr_cell(output_rem);
        let divide_by_zero = curr_cell(output_divide_by_zero);

        // Divide by zero check
        self.constraints
            .push(denominator.clone() * divide_by_zero.clone());
        // Decomposition
        self.constraints.push(
            (numerator.clone() - denominator.clone() * div.clone() - rem.clone())
                * (E::one() - divide_by_zero.clone()),
        );

        (div, rem, divide_by_zero)
    }

    fn and_xor(
        &mut self,
        _lhs: &Self::Variable,
        _rhs: &Self::Variable,
        output_and: Self::Column,
        output_xor: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        // TODO
        (curr_cell(output_and), curr_cell(output_xor))
    }

    fn alloc_scratch(&mut self) -> Self::Column {
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        Column::ScratchState(scratch_idx)
    }

    fn decode(_instruction: &Self::Variable) -> Instruction {
        // TODO(dw): FIXME
        Instruction::RType(RTypeInstruction::Add)
    }

    fn assert_(&mut self, value: &Self::Variable) {
        self.constraints.push(value.clone())
    }

    fn eq_zero_terms(
        &mut self,
        _value: &Self::Variable,
        res_output: Self::Column,
        inv_output: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        (curr_cell(res_output), curr_cell(inv_output))
    }

    fn sign_extend(&mut self, _value: &Self::Variable, output: Self::Column) -> Self::Variable {
        curr_cell(output)
    }
}

pub fn single_instr<F: Field>() -> Vec<Expr<ConstantExpr<F>, Column>> {
    let mut instruction_constraints = vec![];
    for (i, instr) in Instruction::iter().enumerate() {
        if i % (1 << 6) != 0b000000 {
            continue;
        }
        let mut env: InstructionEnv<F> = InstructionEnv {
            halted_set: false,
            constraints: vec![],
            scratch_state_idx: 0,
            lookup_terms_idx: 0,
            lookup_terms: array::from_fn(|_| vec![]),
        };
        interpreter::run_instruction(instr, &mut env);
        for j in 0..NUM_INSTRUCTION_LOOKUP_TERMS {
            // NOTE FOR MORNING
            //
            //
            // YOU ARE CURRENTLY BISECTING THIS
            //
            if i % (1 << 6) != 0b000000 {
                continue;
            }
            if j % (1 << 3) != 0b000 {
                continue;
            }
            //println!("{:#?}", env.lookup_terms[NUM_DECODING_LOOKUP_TERMS + j]);
            // TODO: Make waaaay less manual
            instruction_constraints.push(combine_lookups(
                Column::LookupTerm(NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + j),
                env.lookup_terms[NUM_DECODING_LOOKUP_TERMS + j].clone(),
            ));
        }
        if !env.constraints.is_empty() {
            //println!("{:#?}", env.constraints);
            instruction_constraints.extend(
                env.constraints
                    .into_iter()
                    .map(|x| x * curr_cell(Column::InstructionSelector(instr))),
            );
            let ip = curr_cell(Column::InstructionPointer);
            let ip = ip + E::from(4) - next_cell(Column::Halt) * E::from(4);
            instruction_constraints.push(
                curr_cell(Column::InstructionSelector(instr))
                    * (next_cell(Column::InstructionPointer) - ip.clone()),
            );
            instruction_constraints.push(curr_cell(Column::InstructionPointer));
            instruction_constraints.push(next_cell(Column::InstructionPointer));
            instruction_constraints.push(curr_cell(Column::Halt));
            instruction_constraints.push(ip);
        }
    }
    instruction_constraints
}

pub fn constraints<F: Field + PrimeField>(
    memory_offsets: Vec<u32>,
) -> Expr<ConstantExpr<F>, Column> {
    let mut cache = expr::Cache::default();
    let mut constraints = Vec::new();

    // Check that selectors are boolean
    {
        for rtype in RTypeInstruction::iter() {
            let cell = Column::InstructionSelector(Instruction::RType(rtype));
            constraints.push(boolean(curr_cell(cell)));
        }
        for jtype in JTypeInstruction::iter() {
            let cell = Column::InstructionSelector(Instruction::JType(jtype));
            constraints.push(boolean(curr_cell(cell)));
        }
        for itype in ITypeInstruction::iter() {
            let cell = Column::InstructionSelector(Instruction::IType(itype));
            constraints.push(boolean(curr_cell(cell)));
        }
    };

    // Cache some sums
    let r_type_selectors_sum = {
        RTypeInstruction::iter()
            .map(|rtype| curr_cell(Column::InstructionSelector(Instruction::RType(rtype))))
            .reduce(|x, y| x + y)
            .unwrap()
            .cache(&mut cache)
    };
    let non_rtype_selectors_sum = {
        ((JTypeInstruction::iter().map(Instruction::JType))
            .chain(ITypeInstruction::iter().map(Instruction::IType)))
        .map(Column::InstructionSelector)
        .map(curr_cell::<F>)
        .reduce(|x, y| x + y)
        .unwrap()
        .cache(&mut cache)
    };

    // Check that at most 1 selector is on at any time
    constraints.push(boolean(
        r_type_selectors_sum.clone() + non_rtype_selectors_sum.clone(),
    ));

    // Check that all of the instructions are off on the final row
    constraints.push(
        E::UnnormalizedLagrangeBasis(-1) * (r_type_selectors_sum.clone() + non_rtype_selectors_sum),
    );

    // Check the correctness of the decoding
    // **TODO**: Allow this to fail, propagate the exception
    {
        // NB: Plus one so that opcode 0 has a distinguishable effect
        let expected_opcode_plus_one = ((RTypeInstruction::iter().map(Instruction::RType))
            .chain(JTypeInstruction::iter().map(Instruction::JType))
            .chain(ITypeInstruction::iter().map(Instruction::IType)))
        .map(|selector| {
            let (opcode, _) = encode_selector(selector);
            let opcode = E::from((opcode + 1) as u64);
            opcode * curr_cell(Column::InstructionSelector(selector))
        })
        .reduce(|x, y| x + y)
        .unwrap();

        constraints.push(
            E::VanishesOnZeroKnowledgeAndPreviousRows
                * (expected_opcode_plus_one
                    - curr_cell(Column::InstructionPart(InstructionPart::OpCode))
                    - E::one()),
        )
    }

    // Check the correctness of r-type instruction decoding
    // **TODO**: Allow this to fail, propagate the exception
    {
        // NB: Plus one so that opcode 0 has a distinguishable effect
        let expected_opcode_plus_one = RTypeInstruction::iter()
            .map(|selector| {
                let (_, funct) = encode_rtype(selector);
                let funct = E::from((funct + 1) as u64);
                funct * curr_cell(Column::InstructionSelector(Instruction::RType(selector)))
            })
            .reduce(|x, y| x + y)
            .unwrap();

        constraints.push(
            E::VanishesOnZeroKnowledgeAndPreviousRows
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
        let _ = InstructionEnv::decode_instruction(&mut env);
        constraints.extend(env.constraints);
        for i in 0..NUM_DECODING_LOOKUP_TERMS {
            if i % (1 << 0) != 0b1000 {
                continue;
            }
            /*
            println!("i = {}", i);
            for lookup_term in env.lookup_terms[i].iter() {
                println!("{}", lookup_term);
            }
            */
            // HERE IS FAILING ON THE FINAL ROW!!!!!!!!!!!!!!!!!!
            constraints.push(combine_lookups(
                Column::LookupTerm(NUM_GLOBAL_LOOKUP_TERMS + i),
                env.lookup_terms[i].clone(),
            ));
        }
    }

    // Step the lookup terms
    if env.lookup_terms_idx >= NUM_DECODING_LOOKUP_TERMS {
        panic!("{} > {}", env.lookup_terms_idx, NUM_DECODING_LOOKUP_TERMS);
    }
    env.lookup_terms_idx = NUM_DECODING_LOOKUP_TERMS;

    // Instruction constraints
    {
        let mut instruction_constraints = vec![];
        for (_i, instr) in Instruction::iter().enumerate() {
            if instr != Instruction::IType(ITypeInstruction::BranchNeq) {
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
            interpreter::run_instruction(instr, &mut env);
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
