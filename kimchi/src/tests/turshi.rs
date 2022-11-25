use crate::circuits::{
    gate::CircuitGate,
    polynomials::turshi::{testing::*, witness::*},
};
use mina_curves::pasta::Fp as F;
use turshi::{CairoMemory, CairoProgram};

#[test]
fn test_cairo_should_fail() {
    let instrs = vec![0x480680017fff8000, 10, 0x208b7fff7fff7ffe]
        .iter()
        .map(|&i: &i64| F::from(i))
        .collect();
    let mut mem = CairoMemory::<F>::new(instrs);
    mem.write(F::from(4u32), F::from(7u32)); //beginning of output
    mem.write(F::from(5u32), F::from(7u32)); //end of output
    let prog = CairoProgram::new(&mut mem, 1);

    // Create the Cairo circuit
    let ninstr = prog.trace().len();
    let inirow = 0;
    let (circuit, _) = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

    let mut witness = cairo_witness(&prog);
    // break a witness
    witness[0][0] += F::from(1u32);
    let res_ensure = ensure_cairo_gate(&circuit[0], 0, &witness);
    assert_eq!(Err("wrong initial pc".to_string()), res_ensure);
}

#[test]
fn test_cairo_gate() {
    let instrs = vec![
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
    // TODO(querolita): Need to know how to find out (hints)
    mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
    mem.write(F::from(22u32), F::from(44u32)); // end of outputs
    mem.write(F::from(23u32), F::from(44u32)); //end of program
    let prog = CairoProgram::new(&mut mem, 5);

    let witness = cairo_witness(&prog);

    // Create the Cairo circuit
    let ninstr = prog.trace().len();
    let inirow = 0;
    let (circuit, _) = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res_ensure = ensure_cairo_gate(&gate, row, &witness);
        assert_eq!(Ok(()), res_ensure);
        row += 1;
    }
}
