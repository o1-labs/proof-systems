use ark_ff::PrimeField;
use kimchi_msm::circuit_design::{ColAccessCap, HybridCopyCap};

use super::columns::AdditionColumn;

/// Simply compute A + B - C
pub fn interpreter_simple_add<
    F: PrimeField,
    Env: ColAccessCap<F, AdditionColumn> + HybridCopyCap<F, AdditionColumn>,
>(
    env: &mut Env,
) {
    let a = env.read_column(AdditionColumn::A);
    let b = env.read_column(AdditionColumn::B);
    env.hcopy(&(a.clone() + b.clone()), AdditionColumn::C);
    let c = env.read_column(AdditionColumn::C);
    let eq = a.clone() + b.clone() - c;
    env.assert_zero(eq);
}
