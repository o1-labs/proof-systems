use crate::{
    cannon::{
        Meta, Start, State, StepFrequency, VmConfiguration, PAGE_ADDRESS_MASK, PAGE_ADDRESS_SIZE,
        PAGE_SIZE,
    },
    mips::{
        interpreter::{
            self, ITypeInstruction, Instruction, InstructionPart, InstructionParts, InterpreterEnv,
            JTypeInstruction, RTypeInstruction,
        },
        registers::Registers,
    },
    preimage_oracle::PreImageOracle,
};
use ark_ff::Field;
use log::{debug, info};
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
    pub preimage_key: [u8; 32],
    pub last_hint: Option<Vec<u8>>,
}

impl SyscallEnv {
    pub fn create(state: &State) -> Self {
        SyscallEnv {
            heap: state.heap,
            preimage_key: state.preimage_key,
            preimage_offset: state.preimage_offset,
            last_hint: state.last_hint.clone(),
        }
    }
}

pub struct Env<Fp> {
    pub instruction_parts: InstructionParts<u32>,
    pub instruction_counter: usize,
    pub memory: Vec<(u32, Vec<u8>)>,
    pub memory_write_index: Vec<(u32, Vec<usize>)>,
    pub registers: Registers<u32>,
    pub registers_write_index: Registers<usize>,
    pub instruction_pointer: u32,
    pub next_instruction_pointer: u32,
    pub scratch_state_idx: usize,
    pub scratch_state: [Fp; SCRATCH_SIZE],
    pub halt: bool,
    pub syscall_env: SyscallEnv,
    pub preimage_oracle: PreImageOracle,
}

fn fresh_scratch_state<Fp: Field, const N: usize>() -> [Fp; N] {
    array::from_fn(|_| Fp::zero())
}

const KUNIT: usize = 1024; // a kunit of memory is 1024 things (bytes, kilobytes, ...)
const PREFIXES: &str = "KMGTPE"; // prefixes for memory quantities KiB, MiB, GiB, ...

// Create a human-readable string representation of the memory size
fn memory_size(total: usize) -> String {
    if total < KUNIT {
        format!("{total} B")
    } else {
        // Compute the index in the prefixes string above
        let mut idx = 0;
        let mut d = KUNIT;
        let mut n = total / KUNIT;

        while n >= KUNIT {
            d *= KUNIT;
            idx += 1;
            n /= KUNIT;
        }

        let value = total as f64 / d as f64;

        let prefix =
        ////////////////////////////////////////////////////////////////////////////
        // Famous last words: 1023 exabytes ought to be enough for anybody        //
        //                                                                        //
        // Corollary: unwrap() below shouldn't fail                               //
        //                                                                        //
        // The maximum representation for usize corresponds to 16 exabytes anyway //
        ////////////////////////////////////////////////////////////////////////////
            PREFIXES.chars().nth(idx).unwrap();

        format!("{:.1} {}iB", value, prefix)
    }
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    type Variable = u32;

    fn get_instruction_part(&self, part: InstructionPart) -> Self::Variable {
        self.instruction_parts[part]
    }

    fn set_instruction_pointer(&mut self, ip: Self::Variable) {
        self.instruction_pointer = ip;
        // Set next instruction pointer?
    }

    fn constant(x: u32) -> Self::Variable {
        x
    }

    fn set_halted(&mut self, flag: Self::Variable) {
        if flag == 0 {
            self.halt = false
        } else if flag == 1 {
            self.halt = true
        } else {
            panic!("Bad value for flag in set_halted: {}", flag);
        }
    }
}

impl<Fp: Field> Env<Fp> {
    pub fn create(page_size: usize, state: State, preimage_oracle: PreImageOracle) -> Self {
        let initial_instruction_pointer = state.pc;
        let next_instruction_pointer = state.next_pc;

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
            // Will be modified by decode_instruction.
            // We set the instruction parts to 0 to begin
            instruction_parts: InstructionParts::default(),
            instruction_counter: state.step as usize,
            memory: initial_memory.clone(),
            memory_write_index: memory_offsets
                .iter()
                .map(|offset| (*offset, vec![0usize; page_size]))
                .collect(),
            registers: initial_registers.clone(),
            registers_write_index: Registers::default(),
            instruction_pointer: initial_instruction_pointer,
            next_instruction_pointer,
            scratch_state_idx: 0,
            scratch_state: fresh_scratch_state(),
            halt: state.exited,
            syscall_env,
            preimage_oracle,
        }
    }

    pub fn get_memory_direct(&self, addr: u32) -> u8 {
        const PAGE_ADDRESS_SIZE: u32 = 12;
        const PAGE_SIZE: u32 = 1 << PAGE_ADDRESS_SIZE;
        const PAGE_ADDRESS_MASK: u32 = PAGE_SIZE - 1;
        let page = addr >> PAGE_ADDRESS_SIZE;
        let page_address = (addr & PAGE_ADDRESS_MASK) as usize;
        for (page_index, memory) in self.memory.iter() {
            if *page_index == page {
                return memory[page_address];
            }
        }
        panic!("Could not access address")
    }

    pub fn decode_instruction(&self) -> (Instruction, u32) {
        let instruction = ((self.get_memory_direct(self.instruction_pointer) as u32) << 24)
            | ((self.get_memory_direct(self.instruction_pointer + 1) as u32) << 16)
            | ((self.get_memory_direct(self.instruction_pointer + 2) as u32) << 8)
            | (self.get_memory_direct(self.instruction_pointer + 3) as u32);
        let opcode = {
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
                                Instruction::RType(RTypeInstruction::SyscallReadPreimage)
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
        };
        (opcode, instruction)
    }

    pub fn step(&mut self, config: VmConfiguration, metadata: &Meta, start: &Start) {
        let (opcode, instruction) = self.decode_instruction();
        let op_code = (instruction >> 26) & ((1 << (32 - 26)) - 1);
        let rs = (instruction >> 21) & ((1 << (26 - 21)) - 1);
        let rt = (instruction >> 16) & ((1 << (21 - 16)) - 1);
        let rd = (instruction >> 11) & ((1 << (16 - 11)) - 1);
        let shamt = (instruction >> 6) & ((1 << (11 - 6)) - 1);
        let funct = instruction & ((1 << 6) - 1);
        let instruction_parts: InstructionParts<u32> = InstructionParts {
            op_code,
            rs,
            rt,
            rd,
            shamt,
            funct,
        };
        debug!("instruction: {:?}", opcode);
        debug!("Instruction hex: {:#010x}", instruction);
        debug!("Instruction: {:#034b}", instruction);
        debug!("Rs: {:#07b}", rs);
        debug!("Rt: {:#07b}", rt);
        debug!("Rd: {:#07b}", rd);
        debug!("Shamt: {:#07b}", shamt);
        debug!("Funct: {:#08b}", funct);
        self.instruction_parts = instruction_parts;

        self.pp_info(config.info_at, metadata, start);

        // Force stops at given iteration
        if self.should_trigger_at(config.stop_at) {
            self.halt = true;
            return;
        }

        interpreter::interpret_instruction(self, opcode);
    }

    fn should_trigger_at(&self, at: StepFrequency) -> bool {
        let m: u64 = self.instruction_counter as u64;
        match at {
            StepFrequency::Never => false,
            StepFrequency::Always => true,
            StepFrequency::Exactly(n) => n == m,
            StepFrequency::Every(n) => m % n == 0,
        }
    }

    // Compute memory usage
    fn memory_usage(&self) -> String {
        let total = self.memory.len() * PAGE_SIZE;
        memory_size(total)
    }

    fn page_address(&self) -> (u32, usize) {
        let address = self.instruction_pointer;
        let page = address >> PAGE_ADDRESS_SIZE;
        let page_address = (address & (PAGE_ADDRESS_MASK as u32)) as usize;
        (page, page_address)
    }

    fn get_opcode(&mut self) -> Option<u32> {
        let (page_id, page_address) = self.page_address();
        for (page_index, memory) in self.memory.iter() {
            if page_id == *page_index {
                let memory_slice: [u8; 4] = memory[page_address..page_address + 4]
                    .try_into()
                    .expect("Couldn't read 4 bytes at given address");
                return Some(u32::from_be_bytes(memory_slice));
            }
        }
        None
    }

    fn pp_info(&mut self, at: StepFrequency, meta: &Meta, start: &Start) {
        if self.should_trigger_at(at) {
            let elapsed = start.time.elapsed();
            let step = self.instruction_counter;
            let pc = self.instruction_pointer;

            // Get the 32-bits opcode
            let insn = self.get_opcode().unwrap();

            // Approximate instruction per seconds
            let how_many_steps = step - start.step;
            let ips = how_many_steps as f64 / elapsed.as_secs() as f64;

            let pages = self.memory.len();

            let mem = self.memory_usage();
            let name = meta
                .find_address_symbol(pc)
                .unwrap_or_else(|| "n/a".to_string());

            info!(
                "processing step={} pc={:#010x} insn={:#010x} ips={:.2} page={} mem={} name={}",
                step, pc, insn, ips, pages, mem, name
            );
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_memory_size() {
        assert_eq!(memory_size(1023_usize), "1023 B");
        assert_eq!(memory_size(1024_usize), "1.0 KiB");
        assert_eq!(memory_size(1024 * 1024_usize), "1.0 MiB");
        assert_eq!(memory_size(2100 * 1024 * 1024_usize), "2.1 GiB");
        assert_eq!(memory_size(std::usize::MAX), "16.0 EiB");
    }
}
