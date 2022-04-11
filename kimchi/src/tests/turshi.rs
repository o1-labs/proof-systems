use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::gate::CircuitGate;
use crate::circuits::polynomials::turshi::{testing::*, witness::*};
use ark_ec::AffineCurve;
use cairo::{memory::CairoMemory, runner::CairoProgram};
use mina_curves::pasta::fp::Fp as F;
use mina_curves::pasta::pallas;

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

// creates a constraint system for a number of Cairo instructions
fn create_test_consys(
    inirow: usize,
    ninstr: usize,
) -> (ConstraintSystem<PallasField>, Vec<CircuitGate<PallasField>>) {
    let (gates, _) = CircuitGate::<PallasField>::create_cairo_gadget(inirow, ninstr);
    let cs = ConstraintSystem::create(gates.clone(), vec![], oracle::pasta::fp_kimchi::params(), 0)
        .unwrap();
    (cs, gates)
}

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

    let (cs, circuit) = create_test_consys(inirow, ninstr);
    let mut witness = cairo_witness(&prog);
    // break a witness
    witness[0][0] += F::from(1u32);
    let res_ensure = ensure_cairo_gate(&circuit[0], 0, &witness);
    let res_verify = circuit[0].verify_cairo_gate(0, &witness, &cs);
    assert_eq!(Err("wrong initial pc".to_string()), res_ensure);
    assert_eq!(Err("Invalid CairoClaim constraint".to_string()), res_verify);
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
    let (cs, circuit) = create_test_consys(inirow, ninstr);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res_ensure = ensure_cairo_gate(&gate, row, &witness);
        assert_eq!(Ok(()), res_ensure);
        let res_verify = gate.verify_cairo_gate(row, &witness, &cs);
        assert_eq!(Ok(()), res_verify);
        row = row + 1;
    }
}
