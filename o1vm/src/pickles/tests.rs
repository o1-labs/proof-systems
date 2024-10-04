use crate::{
    interpreters::mips::{
        constraints as mips_constraints, interpreter, interpreter::InterpreterEnv, Instruction,
    },
    pickles::{MAXIMUM_DEGREE_CONSTRAINTS, TOTAL_NUMBER_OF_CONSTRAINTS},
};
use interpreter::{ITypeInstruction, JTypeInstruction, RTypeInstruction};
use kimchi_msm::expr::E;
use mina_curves::pasta::Fp;
use strum::{EnumCount, IntoEnumIterator};

#[test]
fn test_regression_constraints_with_selectors() {
    let constraints = {
        let mut mips_con_env = mips_constraints::Env::<Fp>::default();
        let mut constraints = Instruction::iter()
            .flat_map(|instr_typ| instr_typ.into_iter())
            .fold(vec![], |mut acc, instr| {
                interpreter::interpret_instruction(&mut mips_con_env, instr);
                let selector = mips_con_env.get_selector();
                let constraints_with_selector: Vec<E<Fp>> = mips_con_env
                    .get_constraints()
                    .into_iter()
                    .map(|c| selector.clone() * c)
                    .collect();
                acc.extend(constraints_with_selector);
                mips_con_env.reset();
                acc
            });
        constraints.extend(mips_con_env.get_selector_constraints());
        constraints
    };

    assert_eq!(constraints.len(), TOTAL_NUMBER_OF_CONSTRAINTS);

    let max_degree = constraints.iter().map(|c| c.degree(1, 0)).max().unwrap();
    assert_eq!(max_degree, MAXIMUM_DEGREE_CONSTRAINTS);
}

#[test]
// Sanity check that we have as many selector as we have instructions
fn test_regression_selectors_for_instructions() {
    let mips_con_env = mips_constraints::Env::<Fp>::default();
    let constraints = mips_con_env.get_selector_constraints();
    assert_eq!(
        constraints.len(),
        // We could use N_MIPS_SEL_COLS, but sanity check in case this value is
        // changed.
        RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT
    );
    // All instructions are degree 2.
    constraints
        .iter()
        .for_each(|c| assert_eq!(c.degree(1, 0), 2));
}
