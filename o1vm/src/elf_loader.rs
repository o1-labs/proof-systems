use elf::{endian::LittleEndian, section::SectionHeader, ElfBytes};
use std::{collections::HashMap, path::Path};

/// Parse an ELF file and return the parsed data as a structure that is expected
/// by the o1vm RISCV32i edition.
// FIXME: check the e_machine. Even though it can be modified, let's check that
// we only load supported toolchain and supported architecture. We should use
// Toolchain defined in cannon.rs
// FIXME: parametrize by an architecture. We should return a state depending on the
// architecture. In the meantime, we can have parse_riscv32i and parse_mips.
pub fn parse_riscv32i(path: &Path) -> Result<u64, String> {
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open ELF file failed.");

    // Checking it is RISC-V
    assert_eq!(file.ehdr.e_machine, 243);

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

    // Getting the executable code.
    let text_section = sections_by_name
        .get(".text")
        .expect("Should have .text section");

    // The initial address of the text section is located in the sh_addr field.
    let text_section_start = text_section.sh_addr;

    Ok(text_section_start)
}
