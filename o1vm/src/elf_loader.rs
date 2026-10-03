use crate::cannon::{Page, State, PAGE_SIZE};
use elf::{
    endian::{BigEndian, EndianParse, LittleEndian},
    section::SectionHeader,
    ElfBytes,
};
use log::debug;
use std::{collections::HashMap, path::Path};

pub enum Architecture {
    Mips,
    RiscV32,
}

/// Copy the bytes of the `.text` section into the memory pages it spans.
///
/// The section is described by the half-open interval
/// `[section_start, section_start + section_data.len())`, and a page covers the
/// half-open interval `[page_start, page_start + PAGE_SIZE)`. For each page only
/// the intersection of the two intervals is copied, so page-aligned, unaligned
/// and multi-page sections all go through the very same code path.
///
/// The pages are returned in increasing order of their index, and the index of a
/// page is its "real" index in memory (i.e. the index of the first page is
/// `section_start / PAGE_SIZE`, it is not 0).
fn make_text_pages(section_start: usize, section_data: &[u8]) -> Result<Vec<Page>, String> {
    let page_size: usize = PAGE_SIZE.try_into().unwrap();

    if section_data.is_empty() {
        return Ok(vec![]);
    }

    let section_end = section_start
        .checked_add(section_data.len())
        .ok_or("text section address overflow")?;

    // The last byte of the section lives at `section_end - 1`, and the page it
    // belongs to is the last page we have to allocate.
    let first_page_index = section_start / page_size;
    let last_page_index = (section_end - 1) / page_size;

    let mut memory: Vec<Page> = vec![];
    for page_index in first_page_index..=last_page_index {
        let page_start = page_index
            .checked_mul(page_size)
            .ok_or("page address overflow")?;
        let page_end = page_start + page_size;
        // Only the part of the section that falls into this page is copied.
        let copy_start = section_start.max(page_start);
        let copy_end = section_end.min(page_end);
        let dst_start = copy_start - page_start;
        let src_start = copy_start - section_start;
        let copy_len = copy_end - copy_start;
        let mut data = vec![0; page_size];
        data[dst_start..dst_start + copy_len]
            .copy_from_slice(&section_data[src_start..src_start + copy_len]);
        memory.push(Page {
            index: page_index as u32,
            data,
        });
    }
    Ok(memory)
}

pub fn make_state<T: EndianParse>(file: ElfBytes<T>) -> Result<State, String> {
    // Checking it is RISC-V

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

    // Address of the first byte of the code section.
    let code_section_starting_address = text_section.sh_addr as usize;
    let code_section_size = text_section.sh_size as usize;
    // Address one past the last byte of the code section. The section is a
    // half-open interval, like the pages it is copied into.
    let code_section_end_address = code_section_starting_address
        .checked_add(code_section_size)
        .ok_or("text section address overflow")?;
    debug!(
        "The executable code starts at address {}, has size {} bytes, and ends at address {} (exclusive).",
        code_section_starting_address, code_section_size, code_section_end_address
    );

    if text_section_data.len() < code_section_size {
        return Err(format!(
            "The .text section is truncated: {} bytes are announced, but only {} are available",
            code_section_size,
            text_section_data.len()
        ));
    }
    let text_section_data = &text_section_data[..code_section_size];

    // Building the memory pages
    let memory: Vec<Page> = make_text_pages(code_section_starting_address, text_section_data)?;

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

pub fn parse_elf(arch: Architecture, path: &Path) -> Result<State, String> {
    debug!("Start parsing the ELF file to load a compatible state");
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    match arch {
        Architecture::Mips => {
            let file = ElfBytes::<BigEndian>::minimal_parse(slice).expect("Open ELF file failed.");
            assert_eq!(file.ehdr.e_machine, 8);
            make_state(file)
        }
        Architecture::RiscV32 => {
            let file =
                ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open ELF file failed.");
            assert_eq!(file.ehdr.e_machine, 243);
            make_state(file)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{make_text_pages, PAGE_SIZE};

    const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

    /// A `.text` section whose i-th byte holds `i as u8`. Using a non-constant
    /// content is what makes a truncated or shifted copy visible.
    fn section_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    /// Reference implementation: write the section into the pages byte by byte.
    /// It is intentionally naive, so that it is obviously correct, and it is
    /// used to check `make_text_pages` on arbitrary layouts.
    fn reference_pages(start: usize, data: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut pages: Vec<(u32, Vec<u8>)> = vec![];
        for (i, &byte) in data.iter().enumerate() {
            let address = start + i;
            let index = (address / PAGE_SIZE_USIZE) as u32;
            let offset = address % PAGE_SIZE_USIZE;
            if pages.last().map(|(last, _)| *last) != Some(index) {
                pages.push((index, vec![0; PAGE_SIZE_USIZE]));
            }
            pages.last_mut().unwrap().1[offset] = byte;
        }
        pages
    }

    fn assert_pages(start: usize, len: usize) {
        let data = section_data(len);
        let pages = make_text_pages(start, &data).unwrap_or_else(|e| panic!("{}", e));
        let expected = reference_pages(start, &data);
        assert_eq!(
            pages.len(),
            expected.len(),
            "wrong number of pages for a section starting at {:#x} of size {:#x}",
            start,
            len
        );
        for (page, (index, content)) in pages.iter().zip(expected.iter()) {
            assert_eq!(page.index, *index, "wrong page index");
            assert_eq!(
                page.data, *content,
                "wrong content for page {} (section starting at {:#x} of size {:#x})",
                index, start, len
            );
        }
    }

    /// A section that fits in a single page must be copied in full, including
    /// its last byte. The previous implementation computed the length as
    /// `end - start` with an inclusive `end`, and therefore dropped one byte.
    #[test]
    fn test_single_page_section_copies_the_last_byte() {
        let start = 0x1100;
        let data = section_data(10);
        let pages = make_text_pages(start, &data).unwrap();

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].index, 1);
        // The section is copied at its own address, and nowhere else.
        assert_eq!(&pages[0].data[0x000..0x100], &[0; 0x100][..]);
        assert_eq!(&pages[0].data[0x100..0x10a], &data[..]);
        assert_eq!(pages[0].data[0x10a - 1], 9, "the last byte is missing");
        assert_eq!(&pages[0].data[0x10a..], &[0; PAGE_SIZE_USIZE - 0x10a][..]);
    }

    /// A section that is not page aligned and spans several pages: the first
    /// page must only receive `PAGE_SIZE - (start % PAGE_SIZE)` bytes. The
    /// previous implementation used a full `PAGE_SIZE` length on the first page,
    /// which panicked with an out-of-range slice.
    #[test]
    fn test_unaligned_section_spanning_two_pages() {
        let start = 0x1100;
        let len = 0x1000;
        let data = section_data(len);
        let pages = make_text_pages(start, &data).unwrap();

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].index, 1);
        assert_eq!(pages[1].index, 2);
        // First page: from the start of the section up to the end of the page.
        assert_eq!(&pages[0].data[0x000..0x100], &[0; 0x100][..]);
        assert_eq!(&pages[0].data[0x100..], &data[0x000..0xf00]);
        // Second page: the remainder of the section.
        assert_eq!(&pages[1].data[0x000..0x100], &data[0xf00..0x1000]);
        assert_eq!(&pages[1].data[0x100..], &[0; PAGE_SIZE_USIZE - 0x100][..]);
    }

    /// A section ending exactly on a page boundary must not allocate one extra
    /// page, and its last byte — the last byte of the previous page — must be
    /// copied.
    #[test]
    fn test_section_ending_exactly_on_a_page_boundary() {
        // `start + len` is exactly the beginning of the third page.
        let start = 0x1100;
        let len = 0x1f00;
        let data = section_data(len);
        let pages = make_text_pages(start, &data).unwrap();

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].index, 1);
        assert_eq!(pages[1].index, 2);
        assert_eq!(&pages[0].data[0x100..], &data[0x000..0xf00]);
        assert_eq!(pages[1].data, data[0xf00..0x1f00]);
        // 0x1100 + 0x1f00 - 1 = 0x2fff is the last byte of the second page.
        assert_eq!(pages[1].data[PAGE_SIZE_USIZE - 1], data[len - 1]);
    }

    /// A page aligned section covering exactly one page.
    #[test]
    fn test_page_aligned_section() {
        let pages = make_text_pages(0x1000, &section_data(PAGE_SIZE_USIZE)).unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].index, 1);
        assert_eq!(pages[0].data, section_data(PAGE_SIZE_USIZE));
    }

    /// An empty section does not allocate any page.
    #[test]
    fn test_empty_section() {
        assert!(make_text_pages(0x1100, &[]).unwrap().is_empty());
    }

    /// Cross-check `make_text_pages` against the reference implementation on a
    /// range of sizes and offsets, including sections spanning up to 3 pages.
    #[test]
    fn test_pages_match_a_byte_by_byte_copy() {
        for start in [0x0000, 0x0001, 0x0abc, 0x1000, 0x10ff, 0x1fff, 0x2000] {
            for len in [1, 2, 0xff, 0x100, 0x1000, 0x1001, 0x1abc, 0x2000, 0x3000] {
                assert_pages(start, len);
            }
        }
    }
}
