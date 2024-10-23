use elf::{endian::LittleEndian, ElfBytes};

#[test]
fn test_elf() {
    let curr_dir = std::env::current_dir().unwrap();
    println!("Path: {:?}", curr_dir);
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/test.elf",
    ));
    println!("Path: {:?}", path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open test1");

    // (st is for symbol table/type)
    // (sh is for section header)
    // (shdrs is for section headers)
    // (phdrs is for program headers)
    // (shndx is for section header index)
    // println!("Common sections: {:?}", common_sections);
    // List all segments in the program header, see Program Header in
    // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    println!("ELF header: {:?}", file.ehdr);
    let (shdrs_opt, strtab_opt) = file.section_headers_with_strtab().unwrap();
    println!("Section headers: {:?}", shdrs_opt);
    println!("Section str: {:?}", strtab_opt);

    // Checking it is RISC-V
    assert_eq!(file.ehdr.e_machine, 243);
    file.segments()
        .unwrap()
        .iter()
        .for_each(|h| println!("header: {:?}", h));
}
