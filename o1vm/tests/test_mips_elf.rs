use ark_ff::Field;
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

mod test_oracle {

    use log::debug;
    use o1vm::{
        cannon::{Hint, Preimage},
        preimage_oracle::PreImageOracleT,
    };
    use sha3::{Digest, Keccak256};
    use std::collections::HashMap;

    #[allow(dead_code)]
    #[derive(Debug)]
    enum KeyType {
        // LocalKeyType is for input-type pre-images, specific to the local program instance.
        Local,
        // Keccak256KeyType is for keccak256 pre-images, for any global shared pre-images.
        Keccak256,
        // GlobalGenericKeyType is a reserved key type for generic global data.
        GlobalGeneric,
        // Sha256KeyType is for sha256 pre-images, for any global shared pre-images.
        Sha256,
        // BlobKeyType is for blob point pre-images.
        Blob,
        // PrecompileKeyType is for precompile result pre-images.
        Precompile,
    }

    impl KeyType {
        fn prefix(&self) -> u8 {
            match self {
                // The zero key type is illegal to use, ensuring all keys are non-zero.
                KeyType::Local => 1,
                KeyType::Keccak256 => 2,
                KeyType::GlobalGeneric => 3,
                KeyType::Sha256 => 4,
                KeyType::Blob => 5,
                KeyType::Precompile => 6,
            }
        }

        fn from_prefix(prefix: u8) -> Self {
            match prefix {
                1 => KeyType::Local,
                2 => KeyType::Keccak256,
                3 => KeyType::GlobalGeneric,
                4 => KeyType::Sha256,
                5 => KeyType::Blob,
                6 => KeyType::Precompile,
                _ => panic!("Unknown key type prefix: {}", prefix),
            }
        }
    }

    fn to_preimage_key(kt: KeyType, mut k: [u8; 32]) -> [u8; 32] {
        k[0] = kt.prefix();
        k
    }

    pub struct TestPreImageOracle {
        preimage: [HashMap<[u8; 32], Preimage>; 6],
    }

    impl TestPreImageOracle {
        fn new() -> Self {
            let preimage = std::array::from_fn(|_| HashMap::new());
            TestPreImageOracle { preimage }
        }

        pub fn new_static_oracle(data: Vec<u8>) -> Self {
            let key = {
                let mut hasher = Keccak256::new();
                hasher.update(&data);
                let k = hasher.finalize();
                to_preimage_key(KeyType::Keccak256, k.into())
            };
            let preimage: HashMap<[u8; 32], Preimage> = {
                let mut m = HashMap::new();
                debug!("Inserting preimage for key: {}", hex::encode(key));
                m.insert(key, Preimage::create(data));
                m
            };
            let mut po = Self::new();
            po.preimage[KeyType::Keccak256 as usize] = preimage;
            po
        }

        pub fn new_precompile_oracle() -> Self {
            let precompile: [u8; 20] = {
                let mut a = [0; 20];
                a[19] = 0xa;
                a
            };
            let input = hex::decode("01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d3630624d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a18f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7873033e038326e87ed3e1276fd140253fa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a").expect("failed to decode hex");
            let result = {
                let mut res = vec![0x1];
                let return_value = hex::decode("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001").expect("failed to decode hex");
                res.extend(return_value);
                res
            };
            let key_data = {
                let mut d = Vec::with_capacity(precompile.len() + input.len());
                d.extend_from_slice(&precompile);
                d.extend_from_slice(&input);
                d
            };
            let key = {
                let mut hasher = Keccak256::new();
                hasher.update(&key_data);
                hasher.finalize().into()
            };
            let mut po = Self::new();
            po.preimage[KeyType::Keccak256 as usize].insert(
                to_preimage_key(KeyType::Keccak256, key),
                Preimage::create(key_data),
            );
            po.preimage[KeyType::Precompile as usize].insert(
                to_preimage_key(KeyType::Precompile, key),
                Preimage::create(result),
            );
            po
        }
    }

    impl PreImageOracleT for TestPreImageOracle {
        fn get_preimage(&mut self, key: [u8; 32]) -> Preimage {
            debug!("Asking oracle for key: {}", hex::encode(key));
            let key_type = KeyType::from_prefix(key[0]);
            debug!("Asking oracle for key type {:?}", key_type);
            let m = &self.preimage[key_type as usize];
            match m.get(&key) {
                Some(preimage) => preimage.clone(),
                None => {
                    let key_str = hex::encode(key);
                    panic!("Preimage not found for key {}", key_str)
                }
            }
        }

        fn hint(&mut self, _: Hint) {}
    }
}

struct MipsTest {
    bin_file: PathBuf,
    preimage_oracle: Box<dyn PreImageOracleT>,
}

// currently excluding any oracle based tests and a select group of tests that are failing
fn is_test_excluded(bin_file: &Path) -> bool {
    let file_name = bin_file.file_name().unwrap().to_str().unwrap();
    let untested_programs = [
        "oracle",
        "oracle_kzg",
        "oracle_unaligned_read",
        // "oracle_unaligned_write",
        "exit_group",
        "mul",
    ];
    untested_programs.contains(&file_name)
}

impl MipsTest {
    fn new(bin_file: PathBuf) -> Self {
        let file_name = bin_file.file_name().unwrap().to_str().unwrap();
        if file_name.starts_with("oracle_kzg") {
            MipsTest {
                bin_file,
                preimage_oracle: Box::new(test_oracle::TestPreImageOracle::new_precompile_oracle()),
            }
        } else if file_name.starts_with("oracle") {
            let data = "hello world".as_bytes().to_vec();
            MipsTest {
                bin_file,
                preimage_oracle: Box::new(test_oracle::TestPreImageOracle::new_static_oracle(data)),
            }
        } else {
            MipsTest {
                bin_file,
                preimage_oracle: Box::new(NullPreImageOracle),
            }
        }
    }

    fn parse_state(&self) -> State {
        let curr_dir = std::env::current_dir().unwrap();
        let path = curr_dir.join(self.bin_file.clone());
        o1vm::elf_loader::parse_elf(Architecture::Mips, &path).unwrap()
    }

    fn read_word<Fp: Field, T: PreImageOracleT>(env: &mut witness::Env<Fp, T>, addr: u32) -> u32 {
        let bytes: [u8; 4] = [
            env.get_memory_direct(addr),
            env.get_memory_direct(addr + 1),
            env.get_memory_direct(addr + 2),
            env.get_memory_direct(addr + 3),
        ];
        u32::from_be_bytes(bytes)
    }

    fn run(self) -> Result<(), String> {
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
            self.preimage_oracle,
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
    #[cfg_attr(not(feature = "open_mips"), ignore)]
    fn open_mips_tests() {
        env_logger::init();
        let test_dir = "resources/programs/mips/bin";
        let test_files: Vec<MipsTest> = fs::read_dir(test_dir)
            .unwrap_or_else(|_| panic!("Error reading directory {}", test_dir))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|f| f.is_file() && f.extension().is_none() && !is_test_excluded(f))
            .map(MipsTest::new)
            .collect();

        for test in test_files {
            let test_name = test.bin_file.clone();
            if let Err(err) = test.run() {
                panic!(
                    "Test '{}' failed: {}",
                    test_name.file_name().unwrap().to_str().unwrap(),
                    err
                );
            }
        }
    }
}
