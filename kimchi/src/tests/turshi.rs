use crate::circuits::gate::CircuitGate;
use crate::circuits::polynomials::turshi::*;
use cairo::{memory::CairoMemory, runner::CairoProgram};
use mina_curves::pasta::fp::Fp as F;

#[test]
fn test_cairo_should_fail() {
    let instrs = vec![
        F::from(0x480680017fff8000u64),
        F::from(10u64),
        F::from(0x208b7fff7fff7ffeu64),
    ];
    let mut mem = CairoMemory::<F>::new(instrs);
    mem.write(F::from(4u32), F::from(7u32)); //beginning of output
    mem.write(F::from(5u32), F::from(7u32)); //end of output
    let prog = CairoProgram::new(&mut mem, 1);

    // Create the Cairo circuit
    let ninstr = prog.trace().len();
    let inirow = 0;
    let circuit = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

    let mut witness = cairo_witness(&prog);
    // break a witness
    witness[0][0] += F::from(1u32);
    let res_ensure = circuit[0].ensure_cairo_gate(0, &witness);
    assert_eq!(Err("wrong initial pc".to_string()), res_ensure);
}

#[test]
fn test_cairo_gate() {
    let instrs: Vec<F> = vec![
        F::from(0x400380007ffc7ffdu64),
        F::from(0x482680017ffc8000u64),
        F::from(1),
        F::from(0x208b7fff7fff7ffeu64),
        F::from(0x480680017fff8000u64),
        F::from(10),
        F::from(0x48307fff7fff8000u64),
        F::from(0x48507fff7fff8000u64),
        F::from(0x48307ffd7fff8000u64),
        F::from(0x480a7ffd7fff8000u64),
        F::from(0x48127ffb7fff8000u64),
        F::from(0x1104800180018000u64),
        F::from(-11),
        F::from(0x48127ff87fff8000u64),
        F::from(0x1104800180018000u64),
        -F::from(14),
        F::from(0x48127ff67fff8000u64),
        F::from(0x1104800180018000u64),
        -F::from(17),
        F::from(0x208b7fff7fff7ffeu64),
        /*41, // beginning of outputs
        44,   // end of outputs
        44,   // input
        */
    ];

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
    let circuit = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res_ensure = gate.ensure_cairo_gate(row, &witness);
        assert_eq!(Ok(()), res_ensure);
        row = row + 1;
    }
}
