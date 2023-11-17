use crate::mips::columns::{LookupCounter, LookupCounters};

#[derive(Clone, Debug)]
pub struct Lookup<Fp> {
    pub numerator: Fp,
    pub table_id: Fp,
    pub value: Vec<Fp>,
}

impl<Fp: std::fmt::Display> std::fmt::Display for Lookup<Fp> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "numerator: {}\ntable_id: {}\nvalue:\n[\n",
            self.numerator, self.table_id
        )?;
        for value in self.value.iter() {
            write!(formatter, "\t{}\n", value)?;
        }
        write!(formatter, "]")?;
        Ok(())
    }
}

pub enum TableID {
    Registers,
    Memory,
    RangeCheck16,
    Sparse,
}

pub trait GlobalLookupEnvironment {
    type Fp: From<u64>
        + std::ops::Neg<Output = Self::Fp>
        + std::ops::Add<Self::Fp, Output = Self::Fp>;

    fn initial_memory(&self, idx: usize) -> Self::Fp;
    fn final_memory(&self, idx: usize) -> Self::Fp;
    fn final_memory_write_index(&self, idx: usize) -> Self::Fp;
    fn memory_offset(&self, idx: usize) -> Self::Fp;

    fn initial_registers(&self) -> Self::Fp;
    fn final_registers(&self) -> Self::Fp;
    fn final_registers_write_index(&self) -> Self::Fp;

    fn lookup_counters(&self, col: LookupCounter) -> Self::Fp;

    fn row_number(&self) -> Self::Fp;

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>);
}

struct GlobalLookupEnv<Fp> {
    // Memory
    initial_memory: Vec<u8>,
    final_memory: Vec<u8>,
    final_memory_write_index: Vec<usize>,
    memory_offset: Vec<u32>,
    // Registers
    initial_registers: u32,
    final_registers: u32,
    final_registers_write_index: usize,
    // Current row
    row_number: usize,
    lookups: Vec<Lookup<Fp>>,
    lookup_counters: LookupCounters<usize>,
}

impl<Fp: From<u64> + std::ops::Neg<Output = Fp> + std::ops::Add<Fp, Output = Fp>>
    GlobalLookupEnvironment for GlobalLookupEnv<Fp>
{
    type Fp = Fp;

    fn initial_memory(&self, idx: usize) -> Self::Fp {
        Fp::from(self.initial_memory[idx] as u64)
    }
    fn final_memory(&self, idx: usize) -> Self::Fp {
        Fp::from(self.final_memory[idx] as u64)
    }
    fn final_memory_write_index(&self, idx: usize) -> Self::Fp {
        Fp::from(self.final_memory_write_index[idx] as u64)
    }
    fn memory_offset(&self, idx: usize) -> Self::Fp {
        Fp::from(self.memory_offset[idx] as u64)
    }

    fn initial_registers(&self) -> Self::Fp {
        Fp::from(self.initial_registers as u64)
    }
    fn final_registers(&self) -> Self::Fp {
        Fp::from(self.final_registers as u64)
    }
    fn final_registers_write_index(&self) -> Self::Fp {
        Fp::from(self.final_registers_write_index as u64)
    }

    fn lookup_counters(&self, col: LookupCounter) -> Self::Fp {
        Fp::from(self.lookup_counters[col] as u64)
    }

    fn row_number(&self) -> Self::Fp {
        Fp::from(self.row_number as u64)
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>) {
        self.lookups.push(lookup)
    }
}

pub fn memory_lookups<Env: GlobalLookupEnvironment>(env: &mut Env, memory_idx: usize) {
    env.add_lookup(Lookup {
        numerator: Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Memory as u64),
        value: vec![
            env.initial_memory(memory_idx),
            env.row_number() + env.memory_offset(memory_idx),
        ],
    });
    env.add_lookup(Lookup {
        numerator: -Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Memory as u64),
        value: vec![
            env.final_memory(memory_idx),
            env.row_number() + env.memory_offset(memory_idx),
            env.final_memory_write_index(memory_idx),
        ],
    });
}

pub fn registers_lookups<Env: GlobalLookupEnvironment>(env: &mut Env) {
    env.add_lookup(Lookup {
        numerator: Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Registers as u64),
        value: vec![env.initial_registers(), env.row_number()],
    });
    env.add_lookup(Lookup {
        numerator: -Env::Fp::from(1u64),
        table_id: Env::Fp::from(TableID::Registers as u64),
        value: vec![
            env.final_registers(),
            env.row_number(),
            env.final_registers_write_index(),
        ],
    });
}

pub fn range_check_16_lookups<Env: GlobalLookupEnvironment>(env: &mut Env) {
    env.add_lookup(Lookup {
        numerator: env.lookup_counters(LookupCounter::Counter),
        table_id: Env::Fp::from(TableID::RangeCheck16 as u64),
        value: vec![env.row_number()],
    });
}
