use ark_ff::Field;
use mina_curves::pasta::{Fp, Vesta};
use o1vm::{
    cannon::{self, State, VmConfiguration},
    elf_loader::Architecture,
    interpreters::mips::witness::{self},
    pickles::{cannon_main, DOMAIN_FP, DOMAIN_SIZE},
    preimage_oracle::{NullPreImageOracle, PreImageOracleT},
};
use once_cell::sync::Lazy;
use poly_commitment::{ipa::SRS, SRS as _};

static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
    let srs = SRS::create(DOMAIN_SIZE);
    srs.get_lagrange_basis(DOMAIN_FP.d1);
    srs
});

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

#[test]
fn test_nor_execution() {
    let state = parse_state(String::from("resources/programs/mips/bin/nor"));
    let start = cannon::Start::create(state.step as usize);
    let configuration = VmConfiguration {
        halt_address: Some(0),
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
    assert_eq!(
        read_word(&mut witness, return_register + 4),
        1,
        "Expected done register to be set to 1, got {}",
        done_register
    );

    let result_register = return_register + 8;
    assert_eq!(
        read_word(&mut witness, result_register),
        1,
        "Expected result register to be 1, got {}",
        result_register
    );
}

#[test]
fn test_nor_proving() {
    let state = parse_state(String::from("resources/programs/mips/bin/nor"));
    let start = cannon::Start::create(state.step as usize);
    let configuration = VmConfiguration {
        halt_address: Some(0),
        ..Default::default()
    };
    let witness = witness::Env::<Fp, Box<dyn PreImageOracleT>>::create(
        cannon::PAGE_SIZE as usize,
        state,
        Box::new(NullPreImageOracle),
    );
    cannon_main(configuration, witness, &SRS, start, &None);
}
