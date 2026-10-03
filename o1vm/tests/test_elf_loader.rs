use o1vm::cannon::PAGE_SIZE;
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

    // The .text section of `fibonacci` is mapped at 0x110d4 and is 0xbc bytes
    // long, i.e. it covers [0x110d4, 0x11190). It must be copied in full in the
    // page, last byte included, and nothing else must be written.
    let page = &state.memory[0].data;
    assert_eq!(page.len(), PAGE_SIZE as usize);
    assert_eq!(&page[0x000..0x0d4], &[0u8; 0xd4][..]);
    // First instruction of the program, as given by `objdump -d fibonacci`.
    assert_eq!(&page[0x0d4..0x0d8], &[0x13, 0x01, 0x01, 0xff]);
    // Last instruction of the program, `ret` (0x00008067), little endian.
    assert_eq!(&page[0x18c..0x190], &[0x67, 0x80, 0x00, 0x00]);
    assert_eq!(&page[0x190..], &[0u8; 0x1000 - 0x190][..]);
}

#[test]
// Loading must not panic nor drop any byte, whatever the layout of the .text
// section is: aligned or not, spanning one page or several ones. The programs
// shipped with the repository are all checked here, byte by byte, against the
// content of their .text section.
fn test_text_section_is_copied_in_full() {
    use elf::{endian::LittleEndian, ElfBytes};

    let curr_dir = std::env::current_dir().unwrap();
    let dir = curr_dir.join(std::path::PathBuf::from("resources/programs/riscv32im/bin"));

    let mut programs_checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let file_data = std::fs::read(&path).unwrap();
        let file = ElfBytes::<LittleEndian>::minimal_parse(file_data.as_slice()).unwrap();
        let (shdrs_opt, strtab_opt) = file.section_headers_with_strtab().unwrap();
        let (shdrs, strtab) = (shdrs_opt.unwrap(), strtab_opt.unwrap());
        let text_section = shdrs
            .iter()
            .find(|shdr| strtab.get(shdr.sh_name as usize).unwrap() == ".text")
            .unwrap();
        let (text_data, _) = file.section_data(&text_section).unwrap();
        let section_start = text_section.sh_addr as usize;
        let section_size = text_section.sh_size as usize;

        let state = o1vm::elf_loader::parse_elf(Architecture::RiscV32, &path).unwrap();

        // The section must be spread over the pages it overlaps, and every byte
        // must be readable back at its own address.
        for (i, &expected) in text_data[..section_size].iter().enumerate() {
            let address = section_start + i;
            let page_index = (address / PAGE_SIZE as usize) as u32;
            let page_offset = address % PAGE_SIZE as usize;
            let page = state
                .memory
                .iter()
                .find(|page| page.index == page_index)
                .unwrap_or_else(|| {
                    panic!(
                        "{:?}: address {:#x} lives in page {}, which has not been allocated",
                        path, address, page_index
                    )
                });
            assert_eq!(
                page.data[page_offset], expected,
                "{:?}: wrong byte at address {:#x}",
                path, address
            );
        }
        programs_checked += 1;
    }
    assert!(
        programs_checked > 0,
        "no program found in {:?}, the test did not check anything",
        dir
    );
}
