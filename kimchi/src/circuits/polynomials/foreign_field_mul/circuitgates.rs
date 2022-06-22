use std::marker::PhantomData;

use ark_ff::FftField;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::E,
    gate::GateType,
};

#[derive(Default)]
pub struct ForeignFieldMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignFieldMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignFieldMul0);
    const CONSTRAINTS: u32 = 0;

    fn constraints() -> Vec<E<F>> {
        vec![]
    }
}
