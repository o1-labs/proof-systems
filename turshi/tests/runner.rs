use mina_curves::pasta::Fp as F;
use turshi::{memory::CairoMemory, runner::*};

#[test]
fn test_cairo_step() {
    // This tests that CairoStep works for a 2 word instruction
    //    tempvar x = 10;
    let instrs = [0x480680017fff8000, 10, 0x208b7fff7fff7ffe]
        .iter()
        .map(|&i: &i64| F::from(i))
        .collect();
    let mut mem = CairoMemory::new(instrs);
    // Need to know how to find out
    // Is it final ap and/or final fp? Will write to starkware guys to learn about this
    mem.write(F::from(4u32), F::from(7u32));
    mem.write(F::from(5u32), F::from(7u32));
    let ptrs = CairoState::new(F::from(1u32), F::from(6u32), F::from(6u32));
    let mut step = CairoStep::new(&mut mem, ptrs);

    step.execute();
    assert_eq!(step.next.unwrap().pc, F::from(3u32));
    assert_eq!(step.next.unwrap().ap, F::from(7u32));
    assert_eq!(step.next.unwrap().fp, F::from(6u32));

    println!("{}", step.mem);
}

#[test]
fn test_cairo_program() {
    let instrs = [0x480680017fff8000, 10, 0x208b7fff7fff7ffe]
        .iter()
        .map(|&i: &i64| F::from(i))
        .collect();
    let mut mem = CairoMemory::<F>::new(instrs);
    // Need to know how to find out
    // Is it final ap and/or final fp? Will write to starkware guys to learn about this
    mem.write(F::from(4u32), F::from(7u32)); //beginning of output
    mem.write(F::from(5u32), F::from(7u32)); //end of output
    let prog = CairoProgram::new(&mut mem, 1);
    println!("{}", prog.mem);
}

#[test]
fn test_cairo_output() {
    // This is a test for a longer program, involving builtins, imports and outputs
    // One can generate more tests here: https://www.cairo-lang.org/playground/
    /*
    %builtins output
    from starkware.cairo.common.serialize import serialize_word
    func main{output_ptr : felt*}():
        tempvar x = 10
        tempvar y = x + x
        tempvar z = y * y + x
        serialize_word(x)
        serialize_word(y)
        serialize_word(z)
        return ()
    end
    */
    let instrs = [
        0x400380007ffc7ffd,
        0x482680017ffc8000,
        1,
        0x208b7fff7fff7ffe,
        0x480680017fff8000,
        10,
        0x48307fff7fff8000,
        0x48507fff7fff8000,
        0x48307ffd7fff8000,
        0x480a7ffd7fff8000,
        0x48127ffb7fff8000,
        0x1104800180018000,
        -11,
        0x48127ff87fff8000,
        0x1104800180018000,
        -14,
        0x48127ff67fff8000,
        0x1104800180018000,
        -17,
        0x208b7fff7fff7ffe,
        /*41, // beginning of outputs
        44,   // end of outputs
        44,   // input
        */
    ]
    .iter()
    .map(|&i: &i64| F::from(i))
    .collect();

    let mut mem = CairoMemory::<F>::new(instrs);
    // Need to know how to find out
    mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
    mem.write(F::from(22u32), F::from(44u32)); // end of outputs
    mem.write(F::from(23u32), F::from(44u32)); //end of program
    let prog = CairoProgram::new(&mut mem, 5);
    assert_eq!(prog.fin().pc, F::from(20u32));
    assert_eq!(prog.fin().ap, F::from(41u32));
    assert_eq!(prog.fin().fp, F::from(24u32));
    println!("{}", prog.mem);
    assert_eq!(prog.mem.read(F::from(24u32)).unwrap(), F::from(10u32));
    assert_eq!(prog.mem.read(F::from(25u32)).unwrap(), F::from(20u32));
    assert_eq!(prog.mem.read(F::from(26u32)).unwrap(), F::from(400u32));
    assert_eq!(prog.mem.read(F::from(27u32)).unwrap(), F::from(410u32));
    assert_eq!(prog.mem.read(F::from(28u32)).unwrap(), F::from(41u32));
    assert_eq!(prog.mem.read(F::from(29u32)).unwrap(), F::from(10u32));
    assert_eq!(prog.mem.read(F::from(30u32)).unwrap(), F::from(24u32));
    assert_eq!(prog.mem.read(F::from(31u32)).unwrap(), F::from(14u32));
    assert_eq!(prog.mem.read(F::from(32u32)).unwrap(), F::from(42u32));
    assert_eq!(prog.mem.read(F::from(33u32)).unwrap(), F::from(20u32));
    assert_eq!(prog.mem.read(F::from(34u32)).unwrap(), F::from(24u32));
    assert_eq!(prog.mem.read(F::from(35u32)).unwrap(), F::from(17u32));
    assert_eq!(prog.mem.read(F::from(36u32)).unwrap(), F::from(43u32));
    assert_eq!(prog.mem.read(F::from(37u32)).unwrap(), F::from(410u32));
    assert_eq!(prog.mem.read(F::from(38u32)).unwrap(), F::from(24u32));
    assert_eq!(prog.mem.read(F::from(39u32)).unwrap(), F::from(20u32));
    assert_eq!(prog.mem.read(F::from(40u32)).unwrap(), F::from(44u32));
    assert_eq!(prog.mem.read(F::from(41u32)).unwrap(), F::from(10u32));
    assert_eq!(prog.mem.read(F::from(42u32)).unwrap(), F::from(20u32));
    assert_eq!(prog.mem.read(F::from(43u32)).unwrap(), F::from(410u32));
}
