use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::gate::CircuitGate;
use crate::circuits::polynomials::turshi::*;
use ark_ec::AffineCurve;
use cairo::{memory::CairoMemory, runner::CairoProgram};
use mina_curves::pasta::fp::Fp as F;
use mina_curves::pasta::pallas;

type PallasField = <pallas::Affine as AffineCurve>::BaseField;

// creates a constraint system for a number of Cairo instructions
fn create_test_consys(inirow: usize, ninstr: usize) -> ConstraintSystem<PallasField> {
    let gates = CircuitGate::<PallasField>::create_cairo_gadget(inirow, ninstr);
    ConstraintSystem::create(gates, vec![], oracle::pasta::fp_kimchi::params(), 0).unwrap()
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

    let cs = create_test_consys(inirow, ninstr);

    // Verify each gate
    let mut row = 0;
    for gate in circuit {
        let res_ensure = gate.ensure_cairo_gate(row, &witness);
        if res_ensure.is_err() {
            eprintln!("{:?}", res_ensure);
        }
        let res_verify = gate.verify_cairo_gate(row, &witness, &cs);
        if res_verify.is_err() {
            eprintln!("{:?}", res_verify);
        }
        row = row + 1;
    }
}
