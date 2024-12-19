use crate::cannon::{Page, State, PAGE_SIZE};
use elf::{endian::LittleEndian, section::SectionHeader, ElfBytes};
use log::debug;
use std::{collections::HashMap, path::Path};

/// Parse an ELF file and return the parsed data as a structure that is expected
/// by the o1vm RISC-V 32 bits edition.
// FIXME: parametrize by an architecture. We should return a state depending on the
// architecture. In the meantime, we can have parse_riscv32i and parse_mips.
// FIXME: for now, we return a State structure, either for RISC-V 32i or MIPS.
// We should return a structure specifically built for the o1vm, and not tight
// to Cannon. It will be done in a future PR to avoid breaking the current code
// and have a huge diff.
pub fn parse_riscv32(path: &Path) -> Result<State, String> {
    debug!("Start parsing the ELF file to load a RISC-V 32i compatible state");
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

    debug!("Loading the text section, which contains the executable code.");
    // Getting the executable code.
    let text_section = sections_by_name
        .get(".text")
        .expect("Should have .text section");

    let (text_section_data, _) = file
        .section_data(text_section)
        .expect("Failed to read data from .text section");

    let code_section_starting_address = text_section.sh_addr as usize;
    let code_section_size = text_section.sh_size as usize;
    let code_section_end_address = code_section_starting_address + code_section_size;
    debug!(
        "The executable code starts at address {}, has size {} bytes, and ends at address {}.",
        code_section_starting_address, code_section_size, code_section_end_address
    );

    // Building the memory pages
    let mut memory: Vec<Page> = vec![];
    let page_size_usize: usize = PAGE_SIZE.try_into().unwrap();
    // Padding to get the right number of pages. We suppose that the memory
    // index starts at 0.
    let start_page_address: usize =
        (code_section_starting_address / page_size_usize) * page_size_usize;
    let end_page_address =
        (code_section_end_address / (page_size_usize - 1)) * page_size_usize + page_size_usize;

    let first_page_index = start_page_address / page_size_usize;
    let last_page_index = (end_page_address - 1) / page_size_usize;
    let mut data_offset = 0;
    (first_page_index..=last_page_index).for_each(|page_index| {
        let mut data = vec![0; page_size_usize];
        // Special case of only one page
        if first_page_index == last_page_index {
            let data_length = code_section_end_address - code_section_starting_address;
            let page_offset = code_section_starting_address - start_page_address;
            data[page_offset..page_offset + data_length]
                .copy_from_slice(&text_section_data[0..data_length]);
            data_offset += data_length;
        } else {
            let data_length = if page_index == last_page_index {
                code_section_end_address - (page_index * page_size_usize)
            } else {
                page_size_usize
            };
            let page_offset = if page_index == first_page_index {
                code_section_starting_address - start_page_address
            } else {
                0
            };
            data[page_offset..]
                .copy_from_slice(&text_section_data[data_offset..data_offset + data_length]);
            data_offset += data_length;
        }
        let page = Page {
            index: page_index as u32,
            data,
        };
        memory.push(page);
    });

    // FIXME: add data section into memory for static data saved in the binary

    // FIXME: we're lucky that RISCV32i and MIPS have the same number of
    let registers: [u32; 32] = [0; 32];

    // FIXME: it is only because we share the same structure for the state.
    let preimage_key: [u8; 32] = [0; 32];
    // FIXME: it is only because we share the same structure for the state.
    let preimage_offset = 0;

    // Entry point of the program
    let pc: u32 = file.ehdr.e_entry as u32;
    assert!(pc != 0, "Entry point is 0. The documentation of the ELF library says that it means the ELF doesn't have an entry point. This is not supported. This can happen if the binary given is an object file and not an executable file. You might need to call the linker (ld) before running the binary.");
    let next_pc: u32 = pc + 4u32;

    let state = State {
        memory,
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
