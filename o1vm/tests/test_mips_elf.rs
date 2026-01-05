use ark_ff::PrimeField;
use mina_curves::pasta::Fp;
use o1vm::{
    cannon::{self, State, VmConfiguration},
    elf_loader::Architecture,
    interpreters::mips::witness::{self},
    preimage_oracle::{NullPreImageOracle, PreImageOracleT},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

struct MipsTest {
    bin_file: PathBuf,
}

// currently excluding any oracle based tests and a select group of tests that are failing
fn is_test_excluded(bin_file: &Path) -> bool {
    let file_name = bin_file.file_name().unwrap().to_str().unwrap();
    let untested_programs = ["exit_group", "mul"];
    file_name.starts_with("oracle") || untested_programs.contains(&file_name)
}

impl MipsTest {
    fn parse_state(&self) -> State {
        let curr_dir = std::env::current_dir().unwrap();
        let path = curr_dir.join(&self.bin_file);
        o1vm::elf_loader::parse_elf(Architecture::Mips, &path).unwrap()
    }

    fn read_word<Fp: PrimeField, T: PreImageOracleT>(
        env: &mut witness::Env<Fp, T>,
        addr: u32,
    ) -> u32 {
        let bytes: [u8; 4] = [
            env.get_memory_direct(addr),
            env.get_memory_direct(addr + 1),
            env.get_memory_direct(addr + 2),
            env.get_memory_direct(addr + 3),
        ];
        u32::from_be_bytes(bytes)
    }

    fn run(&self) -> Result<(), String> {
        println!("Running test: {:?}", self.bin_file);
        let mut state = self.parse_state();
        let halt_address = 0xa7ef00d0_u32;
        state.registers[31] = halt_address;

        let start = cannon::Start::create(state.step as usize);
        let configuration = VmConfiguration {
            halt_address: Some(halt_address),
            stop_at: cannon::StepFrequency::Exactly(1000),
            ..Default::default()
        };

        let mut witness = witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
            cannon::PAGE_SIZE as usize,
            state,
            Box::new(NullPreImageOracle),
        );

        while !witness.halt {
            witness.step(&configuration, &None, &start);
        }

        let return_register = 0xbffffff0_u32;
        let done_register = return_register + 4;
        let result_register = return_register + 8;

        let done_value = Self::read_word(&mut witness, done_register);
        if done_value != 1 {
            return Err(format!(
                "Expected done register to be set to 1, got {:#x}",
                done_value
            ));
        }

        let result_value = Self::read_word(&mut witness, result_register);
        if result_value != 1 {
            return Err(format!(
                "Program {:?} failure: expected result register to contain 1, got {:#x}",
                self.bin_file, result_value
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(any(not(feature = "open_mips"), target_os = "macos"), ignore)]
    fn open_mips_tests() {
        let test_dir = "resources/programs/mips/bin";
        let test_files: Vec<MipsTest> = fs::read_dir(test_dir)
            .unwrap_or_else(|_| panic!("Error reading directory {}", test_dir))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|f| f.is_file() && f.extension().is_none() && !is_test_excluded(f))
            .map(|f| MipsTest { bin_file: f })
            .collect();

        for test in test_files {
            let test_name = test.bin_file.file_name().unwrap().to_str().unwrap();
            if let Err(err) = test.run() {
                panic!("Test '{}' failed: {}", test_name, err);
            }
        }
    }
}
