use ark_ff::Field;
use mina_curves::pasta::Fp;
use o1vm::{
    cannon::{self, State, VmConfiguration},
    elf_loader::Architecture,
    interpreters::mips::witness::{self},
    preimage_oracle::{NullPreImageOracle, PreImageOracleT},
};

fn parse_state(fp: String) -> State {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(fp));
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

fn test_single_register_result(prgoram_name: &str, expected: u32) {
    let base_dir = "resources/programs/mips/bin/";
    // this choice was taken from the cannon state_test.go, it is arbitrary
    let halt_address = 0xa7ef00d0_u32;
    let bin_file = format!("{}{}", base_dir, prgoram_name);
    let mut state = parse_state(bin_file);
    // each of the open mips tests end execution with the instruciton 'jr $ra'. As in cannon, we can
    // set $ra to a specific value and test the program counter to signal the program has terminated.
    state.registers[31] = halt_address;
    let start = cannon::Start::create(state.step as usize);
    let configuration = VmConfiguration {
        halt_address: Some(halt_address),
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
    // If you look at the tests, this is always used as a base address to find the registers for
    // signaling the program exit flag and the return result
    let return_register = 0xbffffff0_u32;

    let done_register = return_register + 4;
    assert_eq!(
        read_word(&mut witness, return_register + 4),
        1,
        "Expected done register to be set to 1, got {}",
        done_register
    );

    let result_register = return_register + 8;
    assert_eq!(
        read_word(&mut witness, result_register),
        expected,
        "Program {} failure: expected result register to be {}, got {}",
        prgoram_name,
        expected,
        result_register
    );
    println!("Program {} passed", prgoram_name);
}

#[test]
fn open_mips_tests_execution() {
    test_single_register_result("nor", 0x1);
    test_single_register_result("jr", 0x1);
}
