use super::{
    checked_runner::Constraint,
    constraint_system::KimchiConstraint,
    prelude::{CVar, RunState},
};
use crate::loc;
use ark_ff::PrimeField;
use itertools::Itertools;
use oracle::{
    constants::PlonkSpongeConstantsKimchi, permutation::full_round,
    poseidon::ArithmeticSpongeParams,
};
use std::iter::successors;

const ROUNDS: usize = 55;
const ROUNDS_PER_ROW: usize = 5;

pub fn poseidon<F: PrimeField>(
    runner: &mut RunState<F>,
    preimage: (CVar<F>, CVar<F>),
) -> (CVar<F>, CVar<F>) {
    let initial_state = [preimage.0, preimage.1, CVar::Constant(F::zero())];
    let (constraint, hash) = {
        let mut iter = successors((initial_state, 0_usize).into(), |(prev, i)| {
            let state = round(prev, runner, *i);
            Some((state, i + 1))
        })
        .take(ROUNDS + 1)
        .map(|(r, _)| r);

        let states = iter
            .by_ref()
            .take(ROUNDS - 1)
            .chunks(ROUNDS_PER_ROW)
            .into_iter()
            .flat_map(|mut it| {
                let mut n = || it.next().unwrap();
                let (r0, r1, r2, r3, r4) = (n(), n(), n(), n(), n());
                let state = [r0, r4, r1, r2, r3].into_iter();
                state
            })
            .collect_vec()
            .try_into()
            .unwrap();
        let last = iter.next().unwrap();
        let hash = {
            let [a, b, _] = last.clone();
            (a, b)
        };
        let constraint = Constraint::KimchiConstraint(KimchiConstraint::Poseidon2 { states, last });
        (constraint, hash)
    };
    runner.add_constraint(constraint, Some("Poseidon"));
    hash
}

fn round<F: PrimeField>(
    elements: &[CVar<F>; 3],
    runner: &mut RunState<F>,
    round: usize,
) -> [CVar<F>; 3] {
    let params = params();
    runner.compute(loc!(), |env| {
        let state = elements.clone().map(|var| env.read_var(&var));
        //remove
        let mut state = state.to_vec();
        full_round::<F, PlonkSpongeConstantsKimchi>(&params, &mut state, round);
        state.try_into().unwrap()
    })
}

fn params<F: PrimeField>() -> ArithmeticSpongeParams<F> {
    todo!()
}
