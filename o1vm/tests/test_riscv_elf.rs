use o1vm::interpreters::riscv32i::interpreter::{IInstruction, Instruction, RInstruction};

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
    let state = o1vm::elf_loader::parse_riscv32i(&path).unwrap();
    // This is the output we get by running objdump -d fibonacci
    assert_eq!(state.pc, 69932);
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

    println!("Entry point: {:?}", file.ehdr.e_entry);

    // Checking it is RISC-V
    assert_eq!(file.ehdr.e_machine, 243);

    println!("-----------------------");

    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");
    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab"),
    );

    // Parse the shdrs and collect them into a map keyed on their zero-copied name
    let sections_by_name: HashMap<&str, SectionHeader> = shdrs
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

    // read all symbols
    let symtab = file.symbol_table().expect("Failed to read symbol table");

    println!("Symbol table: {:?}", symtab);

    // First, we need to get the executable code. The executable code is located in the .text section.
    // FIXME: handle empty code... Should not happen but we never know.
    let text_section = sections_by_name
        .get(".text")
        .expect("Should have .text section");

    let (text_data, _) = file
        .section_data(text_section)
        .expect("Failed to read data from .text section");

    // The initial address of the text section is located in the sh_addr field.
    let text_section_start = text_section.sh_addr;
    println!("Text section header address: {:?}", text_section_start);
    println!("Text section size: {:?}", text_section.sh_size);
    println!(
        "Text section end address: {:?}",
        text_section_start + text_section.sh_size
    );
    println!("Data bytes at start of text section: {:?}", text_section);
    println!("First bytes of text section: {:?}", &text_data[0..4]);

    // FIXME: handle empty data. Ignoring for now.
    let data_section = sections_by_name.get(".data");

    println!("Text section: {:?}", text_section);
    println!("Data section: {:?}", data_section);

    sections_by_name.iter().for_each(|(name, shdr)| {
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

#[test]
// Checking an instruction can be converted into a string.
// It is mostly because we would want to use it to debug or write better error
// messages.
fn test_instruction_can_be_converted_into_string() {
    let instruction = Instruction::RType(RInstruction::Add);
    assert_eq!(instruction.to_string(), "add");

    let instruction = Instruction::RType(RInstruction::Sub);
    assert_eq!(instruction.to_string(), "sub");

    let instruction = Instruction::IType(IInstruction::LoadByte);
    assert_eq!(instruction.to_string(), "lb");

    let instruction = Instruction::IType(IInstruction::LoadHalf);
    assert_eq!(instruction.to_string(), "lh");
}
