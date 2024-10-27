use elf::{endian::LittleEndian, section::SectionHeader, ElfBytes};
use std::{collections::HashMap, path::Path};

use crate::cannon::State;

/// Parse an ELF file and return the parsed data as a structure that is expected
/// by the o1vm RISCV32i edition.
// FIXME: check the e_machine. Even though it can be modified, let's check that
// we only load supported toolchain and supported architecture. We should use
// Toolchain defined in cannon.rs
// FIXME: parametrize by an architecture. We should return a state depending on the
// architecture. In the meantime, we can have parse_riscv32i and parse_mips.
// FIXME: for now, we return a State structure, either for RISCV32i or MIPS. We should
// return a structure specifically built for the o1vm, and not tight to Cannon.
// This is only to get somethign done quickly.
pub fn parse_riscv32i(path: &Path) -> Result<State, String> {
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
    let _text_section = sections_by_name
        .get(".text")
        .expect("Should have .text section");

    // FIXME: we're lucky that RISCV32i and MIPS have the same number of
    // registers.
    let registers: [u32; 32] = [0; 32];

    // FIXME: it is only because we share the same structure for the state.
    let preimage_key: [u8; 32] = [0; 32];
    // FIXME: it is only because we share the same structure for the state.
    let preimage_offset = 0;

    // Entry point of the program
    let pc: u32 = file.ehdr.e_entry as u32;
    assert!(pc != 0, "Entry point is 0. The documentation of the ELF library says that it means the ELF doesn't have an entry point. This is not supported.");
    let next_pc: u32 = pc + 4u32;

    let state = State {
        // FIXME: initialize correct above with the data and text section
        memory: vec![],
        // FIXME: only because Cannon related
        preimage_key,
        // FIXME: only because Cannon related
        preimage_offset,
        pc,
        next_pc,
        // FIXME: only because Cannon related
        lo: 0,
        // FIXME: only because Cannon related
        hi: 0,
        heap: 0,
        exit: 0,
        exited: false,
        step: 0,
        registers,
        // FIXME: only because Cannon related
        last_hint: None,
        // FIXME: only because Cannon related
        preimage: None,
    };

    Ok(state)
}
