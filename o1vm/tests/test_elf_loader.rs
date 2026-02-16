use o1vm::elf_loader::Architecture;

#[test]
// This test is used to check that the elf loader is working correctly.
// We must export the code used in this test in a function that can be called by
// the o1vm at load time.
fn test_correctly_parsing_elf() {
    let curr_dir = std::env::current_dir().unwrap();
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32im/bin/fibonacci",
    ));
    let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();

    // This is the output we get by running objdump -d fibonacci
    assert_eq!(state.pc, 69932);

    // We do have only one page of memory
    assert_eq!(state.memory.len(), 1);
    // Which is the 17th
    assert_eq!(state.memory[0].index, 17);
}
