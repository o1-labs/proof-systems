use ark_ff::One;
use mina_curves::pasta::Fp as F;
use turshi::CairoMemory;

#[test]
fn test_cairo_bytecode() {
    // This test starts with the public memory corresponding to a simple Cairo program
    // func main{}():
    //    tempvar x = 10;
    //    return()
    // end
    // And checks that memory writing and reading works as expected by completing
    // the total memory of executing the program
    let instrs = [0x480680017fff8000, 10, 0x208b7fff7fff7ffe]
        .iter()
        .map(|&i: &i64| F::from(i))
        .collect();
    let mut memory = CairoMemory::new(instrs);
    memory.write(F::from(memory.len()), F::from(7u64));
    memory.write(F::from(memory.len()), F::from(7u64));
    memory.write(F::from(memory.len()), F::from(10u64));
    println!("{memory}");
    // Check content of an address
    assert_eq!(
        memory.read(F::one()).unwrap(),
        F::from(0x480680017fff8000u64)
    );
    // Check that the program contained 3 words
    assert_eq!(3, memory.get_codelen());
    // Check we have 6 words, excluding the dummy entry
    assert_eq!(6, memory.len() - 1);
    memory.read(F::from(10u32));
}
