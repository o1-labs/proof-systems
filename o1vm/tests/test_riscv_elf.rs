use elf::{endian::LittleEndian, ElfBytes};

#[test]
fn test_elf() {
    let curr_dir = std::env::current_dir().unwrap();
    println!("Path: {:?}", curr_dir);
    let path = curr_dir.join(std::path::PathBuf::from(
        "resources/programs/riscv32i/basic.elf",
    ));
    println!("Path: {:?}", path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open test1");

    println!("File: {:?}", file);
}
