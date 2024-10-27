use std::collections::HashMap;

use elf::{endian::LittleEndian, section::SectionHeader, ElfBytes};

#[test]
// This test is used to check that the elf loader is working correctly.
// We must export the code used in this test in a function that can be called by
// the o1vm at load time.
fn test_correctly_parsing_elf() {
    let executable_name = "fibonacci";
    let curr_dir = std::env::current_dir().unwrap();
    println!("Path: {:?}", curr_dir);
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/".to_owned() + executable_name,
    ));
    println!("Path: {:?}", path);
    let text_section_start = o1vm::elf_loader::parse_elf(&path);
    // This is the output we get by running objdump -d fibonacci
    assert_eq!(text_section_start.unwrap(), 69844);
}

#[test]
fn test_elf() {
    let executable_name = "fibonacci";
    let curr_dir = std::env::current_dir().unwrap();
    println!("Path: {:?}", curr_dir);
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/".to_owned() + executable_name,
    ));
    println!("Path: {:?}", path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open ELF file failed.");
    // (st is for symbol table/type)
    // (sh is for section header)
    // (shdrs is for section headers)
    // (phdrs is for program headers)
    // (shndx is for section header index)
    // println!("Common sections: {:?}", common_sections);
    // List all segments in the program header, see Program Header in
    // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    println!("ELF header: {:?}", file.ehdr);

    // Checking it is RISC-V
    assert_eq!(file.ehdr.e_machine, 243);

    println!("-----------------------");

    // Get the section header table alongside its string table
    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");
    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab"),
    );

    // Parse the shdrs and collect them into a map keyed on their zero-copied name
    let with_names: HashMap<&str, SectionHeader> = shdrs
        .iter()
        .map(|shdr| {
            (
                strtab
                    .get(shdr.sh_name as usize)
                    .expect("Failed to get section name"),
                shdr,
            )
        })
        .collect();

    // FIXME: handle empty code... Should not happen but we never know.
    let text_section = with_names.get(".text").expect("Should have .text section");
    // FIXME: handle empty data. Ignoring for now.
    let data_section = with_names.get(".data");

    println!("Text section: {:?}", text_section);
    println!("Data section: {:?}", data_section);

    with_names.iter().for_each(|(name, shdr)| {
        println!("Section header: {:?} {:?}", name, shdr);
    });

    // The code is located in the .text section (starting at address 69844).
    // This is where the executable code is.

    // file.segments()
    //     .unwrap()
    //     .iter()
    //     .for_each(|h| println!("header: {:?}", h));

    // let executable_code = file
    //     .segments()
    //     .unwrap()
    //     .iter()
    //     .find(|h| h.p_flags == 0x04)
    //     .unwrap();

    // println!("Executable code: {:?}", executable_code);
}
