use crate::{
    cannon::State,
    mips::{
        interpreter::{self, ITypeInstruction, Instruction, JTypeInstruction, RTypeInstruction},
        registers::Registers,
    },
};
use ark_ff::Field;
use std::array;

pub const NUM_GLOBAL_LOOKUP_TERMS: usize = 1;
pub const NUM_DECODING_LOOKUP_TERMS: usize = 2;
pub const NUM_INSTRUCTION_LOOKUP_TERMS: usize = 5;
pub const NUM_LOOKUP_TERMS: usize =
    NUM_GLOBAL_LOOKUP_TERMS + NUM_DECODING_LOOKUP_TERMS + NUM_INSTRUCTION_LOOKUP_TERMS;
pub const SCRATCH_SIZE: usize = 25;

#[derive(Clone)]
pub struct SyscallEnv {
    pub heap: u32, // Heap pointer (actually unused in Cannon as of [2023-10-18])
    pub preimage_offset: u32,
    pub preimage_key: Vec<u8>,
    pub last_hint: Option<Vec<u8>>,
}

impl SyscallEnv {
    pub fn create(state: &State) -> Self {
        SyscallEnv {
            heap: state.heap,
            preimage_key: state.preimage_key.as_bytes().to_vec(), // Might not be correct
            preimage_offset: state.preimage_offset,
            last_hint: state.last_hint.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Env<Fp> {
    pub instruction_counter: usize,
    pub memory: Vec<(u32, Vec<u8>)>,
    pub memory_write_index: Vec<(u32, Vec<usize>)>,
    pub registers: Registers<u32>,
    pub registers_write_index: Registers<usize>,
    pub instruction_pointer: u32,
    pub scratch_state_idx: usize,
    pub scratch_state: [Fp; SCRATCH_SIZE],
    pub halt: bool,
    pub syscall_env: SyscallEnv,
}

fn fresh_scratch_state<Fp: Field, const N: usize>() -> [Fp; N] {
    array::from_fn(|_| Fp::zero())
}

impl<Fp: Field> Env<Fp> {
    pub fn create(page_size: usize, state: State) -> Self {
        let initial_instruction_pointer = state.pc;

        let syscall_env = SyscallEnv::create(&state);

        let mut initial_memory: Vec<(u32, Vec<u8>)> = state
            .memory
            .into_iter()
            // Check that the conversion from page data is correct
            .map(|page| (page.index, page.data))
            .collect();

        for (_address, initial_memory) in initial_memory.iter_mut() {
            initial_memory.extend((0..(page_size - initial_memory.len())).map(|_| 0u8));
            assert_eq!(initial_memory.len(), page_size);
        }

        let memory_offsets = initial_memory
            .iter()
            .map(|(offset, _)| *offset)
            .collect::<Vec<_>>();

        let initial_registers = Registers {
            lo: state.lo,
            hi: state.hi,
            general_purpose: state.registers,
        };

        Env {
            instruction_counter: state.step as usize,
            memory: initial_memory.clone(),
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0usize; page_size]))
                .collect(),
            registers: initial_registers.clone(),
            registers_write_index: Registers::default(),
            instruction_pointer: initial_instruction_pointer,
            scratch_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            halt: state.exited,
            syscall_env,
        }
    }

    pub fn get_memory_direct(&self, addr: u32) -> u8 {
        const PAGE_ADDRESS_SIZE: u32 = 12;
        const PAGE_SIZE: u32 = 1 << PAGE_ADDRESS_SIZE;
        const PAGE_ADDRESS_MASK: u32 = PAGE_SIZE - 1;
        let page = (addr >> PAGE_ADDRESS_SIZE) as u32;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        for (page_index, memory) in self.memory.iter() {
            if *page_index == page {
                return memory[page_address];
            }
        }
        panic!("Could not access address")
    }

    pub fn decode_instruction(&self) -> Instruction {
        let instruction = ((self.get_memory_direct(self.instruction_pointer) as u32) << 24)
            | ((self.get_memory_direct(self.instruction_pointer + 1) as u32) << 16)
            | ((self.get_memory_direct(self.instruction_pointer + 2) as u32) << 8)
            | (self.get_memory_direct(self.instruction_pointer + 3) as u32);
        match instruction >> 26 {
            0x00 => match instruction & 0x3F {
                0x00 => Instruction::RType(RTypeInstruction::ShiftLeftLogical),
                0x02 => Instruction::RType(RTypeInstruction::ShiftRightLogical),
                0x03 => Instruction::RType(RTypeInstruction::ShiftRightArithmetic),
                0x04 => Instruction::RType(RTypeInstruction::ShiftLeftLogicalVariable),
                0x06 => Instruction::RType(RTypeInstruction::ShiftRightLogicalVariable),
                0x07 => Instruction::RType(RTypeInstruction::ShiftRightArithmeticVariable),
                0x08 => Instruction::RType(RTypeInstruction::JumpRegister),
                0x09 => Instruction::RType(RTypeInstruction::JumpAndLinkRegister),
                0x0a => Instruction::RType(RTypeInstruction::MoveZero),
                0x0b => Instruction::RType(RTypeInstruction::MoveNonZero),
                0x0c => match self.registers.general_purpose[2] {
                    4090 => Instruction::RType(RTypeInstruction::SyscallMmap),
                    4045 => {
                        // sysBrk
                        Instruction::RType(RTypeInstruction::SyscallOther)
                    }
                    4120 => {
                        // sysClone
                        Instruction::RType(RTypeInstruction::SyscallOther)
                    }
                    4246 => Instruction::RType(RTypeInstruction::SyscallExitGroup),
                    4003 => match self.registers.general_purpose[4] {
                        interpreter::FD_PREIMAGE_READ => {
                            Instruction::RType(RTypeInstruction::SyscallReadPrimage)
                        }
                        _ => Instruction::RType(RTypeInstruction::SyscallReadOther),
                    },
                    4004 => match self.registers.general_purpose[4] {
                        interpreter::FD_PREIMAGE_WRITE => {
                            Instruction::RType(RTypeInstruction::SyscallWritePreimage)
                        }
                        interpreter::FD_HINT_WRITE => {
                            Instruction::RType(RTypeInstruction::SyscallWriteHint)
                        }
                        _ => Instruction::RType(RTypeInstruction::SyscallWriteOther),
                    },
                    4055 => Instruction::RType(RTypeInstruction::SyscallFcntl),
                    _ => {
                        // NB: This has well-defined behavior. Don't panic!
                        Instruction::RType(RTypeInstruction::SyscallOther)
                    }
                },
                0x0f => Instruction::RType(RTypeInstruction::Sync),
                0x10 => Instruction::RType(RTypeInstruction::MoveFromHi),
                0x11 => Instruction::RType(RTypeInstruction::MoveToHi),
                0x12 => Instruction::RType(RTypeInstruction::MoveFromLo),
                0x13 => Instruction::RType(RTypeInstruction::MoveToLo),
                0x18 => Instruction::RType(RTypeInstruction::Multiply),
                0x19 => Instruction::RType(RTypeInstruction::MultiplyUnsigned),
                0x1a => Instruction::RType(RTypeInstruction::Div),
                0x1b => Instruction::RType(RTypeInstruction::DivUnsigned),
                0x20 => Instruction::RType(RTypeInstruction::Add),
                0x21 => Instruction::RType(RTypeInstruction::AddUnsigned),
                0x22 => Instruction::RType(RTypeInstruction::Sub),
                0x23 => Instruction::RType(RTypeInstruction::SubUnsigned),
                0x24 => Instruction::RType(RTypeInstruction::And),
                0x25 => Instruction::RType(RTypeInstruction::Or),
                0x26 => Instruction::RType(RTypeInstruction::Xor),
                0x2a => Instruction::RType(RTypeInstruction::SetLessThan),
                0x2b => Instruction::RType(RTypeInstruction::SetLessThanUnsigned),
                _ => {
                    panic!("Unhandled instruction {:#X}", instruction)
                }
            },
            0x02 => Instruction::JType(JTypeInstruction::Jump),
            0x03 => Instruction::JType(JTypeInstruction::JumpAndLink),
            0x08 => Instruction::IType(ITypeInstruction::AddImmediate),
            0x09 => Instruction::IType(ITypeInstruction::AddImmediateUnsigned),
            0x0A => Instruction::IType(ITypeInstruction::SetLessThanImmediate),
            0x0B => Instruction::IType(ITypeInstruction::SetLessThanImmediateUnsigned),
            0x0C => Instruction::IType(ITypeInstruction::AndImmediate),
            0x0D => Instruction::IType(ITypeInstruction::OrImmediate),
            0x0E => Instruction::IType(ITypeInstruction::XorImmediate),
            0x0F => Instruction::IType(ITypeInstruction::LoadUpperImmediate),
            0x1C => match instruction & 0x3F {
                0x02 => Instruction::RType(RTypeInstruction::MultiplyToRegister),
                0x20 => Instruction::RType(RTypeInstruction::CountLeadingZeros),
                0x21 => Instruction::RType(RTypeInstruction::CountLeadingOnes),
                _ => panic!("Unhandled instruction {:#X}", instruction),
            },
            0x20 => Instruction::IType(ITypeInstruction::Load8),
            0x21 => Instruction::IType(ITypeInstruction::Load16),
            0x22 => Instruction::IType(ITypeInstruction::LoadWordLeft),
            0x23 => Instruction::IType(ITypeInstruction::Load32),
            0x24 => Instruction::IType(ITypeInstruction::Load8Unsigned),
            0x25 => Instruction::IType(ITypeInstruction::Load16Unsigned),
            0x26 => Instruction::IType(ITypeInstruction::LoadWordRight),
            0x28 => Instruction::IType(ITypeInstruction::Store8),
            0x29 => Instruction::IType(ITypeInstruction::Store16),
            0x2a => Instruction::IType(ITypeInstruction::StoreWordLeft),
            0x2b => Instruction::IType(ITypeInstruction::Store32),
            0x2e => Instruction::IType(ITypeInstruction::StoreWordRight),
            0x30 => {
                // Note: This is ll (LoadLinked), but we're only simulating a single processor.
                Instruction::IType(ITypeInstruction::Load32)
            }
            0x38 => {
                // Note: This is sc (StoreConditional), but we're only simulating a single processor.
                Instruction::IType(ITypeInstruction::Store32)
            }
            _ => {
                panic!("Unhandled instruction {:#X}", instruction)
            }
        }
    }

    pub fn step(&mut self) {
        println!("instruction: {:?}", self.decode_instruction());
        // TODO
        self.halt = true;
    }
}
