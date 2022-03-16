use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::gate::CircuitGate;
use crate::circuits::polynomials::turshi::*;
use ark_ec::AffineCurve;
use cairo::{helper::*, memory::CairoMemory, runner::CairoProgram};
use mina_curves::pasta::fp::Fp as F;
use mina_curves::pasta::pallas;

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

// creates a constraint system for a number of Cairo instructions
fn create_test_consys(inirow: usize, ninstr: usize) -> ConstraintSystem<PallasField> {
    let gates = CircuitGate::<PallasField>::create_cairo_gadget(inirow, ninstr);
    ConstraintSystem::create(gates, vec![], oracle::pasta::fp_kimchi::params(), 0).unwrap()
}

#[test]
fn test_cairo_cs() {
    let instrs: Vec<i128> = vec![
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
    ];

    let mut mem = CairoMemory::<F>::new(F::vec_to_field(&instrs));
    // Need to know how to find out
    mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
    mem.write(F::from(22u32), F::from(44u32)); // end of outputs
    mem.write(F::from(23u32), F::from(44u32)); //end of program
    let prog = CairoProgram::new(&mut mem, 5, 24);

    let witness = cairo_witness(&prog);

    // Create the Cairo circuit
    let ninstr = prog.trace().len();
    let inirow = 0;
    let circuit = CircuitGate::<F>::create_cairo_gadget(inirow, ninstr);

    let cs = create_test_consys(inirow, ninstr);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res = gate.verify_cairo_gate(row, &witness, &cs);
        if res.is_err() {
            println!("{:?}", res);
        }
        row = row + 1;
    }
}

#[test]
fn test_long_cairo_gate() {
    let instrs: Vec<i128> = vec![
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
    ];

    let mut mem = CairoMemory::<F>::new(F::vec_to_field(&instrs));
    // Need to know how to find out
    mem.write(F::from(21u32), F::from(41u32)); // beginning of outputs
    mem.write(F::from(22u32), F::from(44u32)); // end of outputs
    mem.write(F::from(23u32), F::from(44u32)); //end of program
    let prog = CairoProgram::new(&mut mem, 5, 24);

    let witness = cairo_witness(&prog);
    //view_witness(&witness);

    // Create the Cairo circuit
    let num = prog.trace().len();
    let circuit = CircuitGate::<F>::create_cairo_gadget(0, num);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res = gate.ensure_cairo_gate(row, &witness);
        if res.is_err() {
            println!("{:?}", res);
        }
        row = row + 1;
    }
}
#[test]
fn test_cairo_gate() {
    // Compute the Cairo witness
    let instrs = vec![
        F::from(0x480680017fff8000u64),
        F::from(10u64),
        F::from(0x208b7fff7fff7ffeu64),
    ];
    let mut mem = CairoMemory::<F>::new(instrs);
    mem.write(F::from(4u32), F::from(7u32)); //beginning of output
    mem.write(F::from(5u32), F::from(7u32)); //end of output
    let prog = CairoProgram::new(&mut mem, 1, 6);
    let witness = cairo_witness(&prog);
    //view_witness(&witness);

    // Create the Cairo circuit
    let num = prog.trace().len();
    let circuit = CircuitGate::<F>::create_cairo_gadget(0, num);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res = gate.ensure_cairo_gate(row, &witness);
        if res.is_err() {
            println!("{:?}", res);
        }
        row = row + 1;
    }
}
