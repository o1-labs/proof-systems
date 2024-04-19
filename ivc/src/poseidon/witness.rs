use crate::poseidon::interpreter::{Column, Params, PoseidonInterpreter};
use ark_ff::Field;
use std::marker::PhantomData;

pub struct PoseidonWitness<F: Field, const S: usize, const R: usize, P: Params<F, S, R>> {
    input: [F; S],
    rounds: [[F; S]; R],
    mds: [[F; S]; S],
    round_constants: [[F; S]; R],
    _p: PhantomData<P>,
}

impl<F: Field + Default, const S: usize, const R: usize, P: Params<F, S, R> + Default> Default
    for PoseidonWitness<F, S, R, P>
{
    fn default() -> Self {
        let round_constants = P::constants();
        let mds = P::mds();
        Self {
            input: [F::zero(); S],
            rounds: [[F::zero(); S]; R],
            mds,
            round_constants,
            _p: PhantomData,
        }
    }
}

impl<F: Field, const S: usize, const R: usize, P: Params<F, S, R>> PoseidonInterpreter<F, S, R>
    for PoseidonWitness<F, S, R, P>
{
    type Variable = F;

    fn constrain(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero());
    }

    fn write(&mut self, x: &Self::Variable, to: Column) -> Self::Variable {
        let col = match to {
            Column::Input(i) => &mut self.input[i],
            Column::Round(round, i) => &mut self.rounds[round][i],
        };
        *col = *x;
        *col
    }

    fn read_column(&self, col: Column) -> Self::Variable {
        match col {
            Column::Input(i) => self.input[i],
            Column::Round(round, i) => self.rounds[round][i],
        }
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn round_constants(&self) -> &[[Self::Variable; S]; R] {
        &self.round_constants
    }

    fn mds(&self) -> &[[Self::Variable; S]; S] {
        &self.mds
    }

    fn sbox(&self, v: Self::Variable) -> Self::Variable {
        v.pow([7])
    }
}
